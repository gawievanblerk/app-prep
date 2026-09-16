"""Extract data models from Prisma, SQL, Django, SQLAlchemy and Drizzle."""

from __future__ import annotations

import ast
import re
from pathlib import PurePosixPath

from dpr.model import DataModel, Field, Location
from dpr.parsing import jsts, pyast
from dpr.parsing.prisma import parse_prisma
from dpr.parsing.sqlschema import SchemaState
from dpr.walk import RepoIndex

DJANGO_FIELD = re.compile(r"^\w*(Field|ForeignKey|OneToOneField|ManyToManyField)$")
DJANGO_AUTO = ("AutoField", "BigAutoField", "SmallAutoField")
SA_COLUMN = re.compile(r"^(?:\w+\.)*(Column|mapped_column)$")
DRIZZLE_TABLE = re.compile(r"(?:\w+\.)?(pgTable|mysqlTable|sqliteTable)")


def _prisma(index: RepoIndex) -> list[DataModel]:
    models = []
    for entry in index.glob("*.prisma"):
        for model in parse_prisma(index.text(entry.rel)):
            fields = tuple(
                Field(
                    name=f.name,
                    type=f.type + ("[]" if f.is_list else ""),
                    location=Location(entry.rel, f.line),
                    unique="@unique" in f.attributes or "@id" in f.attributes,
                    autoincrement="autoincrement()" in f.attributes,
                )
                for f in model.fields
            )
            location = Location(entry.rel, model.line)
            models.append(DataModel(model.name, model.table, "prisma", location, fields))
    return models


def _sql(state: SchemaState) -> list[DataModel]:
    models = []
    for table in state.tables.values():
        fields = tuple(
            Field(c.name, c.type, table.location, c.unique, c.autoincrement) for c in table.columns
        )
        models.append(DataModel(table.name, table.key, "sql", table.location, fields))
    return models


def _django_model(entry_rel: str, cls: ast.ClassDef) -> DataModel | None:
    meta = next((n for n in cls.body if isinstance(n, ast.ClassDef) and n.name == "Meta"), None)
    meta_values = pyast.assignments(meta.body) if meta else {}
    if pyast.constant(meta_values.get("abstract")) is True:
        return None
    fields: list[Field] = []
    has_pk = False
    for stmt in cls.body:
        if not (isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call)):
            continue
        if len(stmt.targets) != 1 or not isinstance(stmt.targets[0], ast.Name):
            continue
        kind = (pyast.dotted(stmt.value.func) or "").split(".")[-1]
        if not DJANGO_FIELD.match(kind):
            continue
        pk = pyast.constant(pyast.kwarg(stmt.value, "primary_key")) is True
        unique = pk or pyast.constant(pyast.kwarg(stmt.value, "unique")) is True
        has_pk = has_pk or pk
        fields.append(Field(stmt.targets[0].id, kind, Location(entry_rel, stmt.lineno), unique,
                            kind in DJANGO_AUTO))
    if not has_pk:
        fields.insert(0, Field("id", "BigAutoField", Location(entry_rel, cls.lineno), True, True))
    path = PurePosixPath(entry_rel)
    app = path.parent.parent.name if path.parent.name == "models" else path.parent.name
    table = pyast.constant(meta_values.get("db_table"), None)
    if not isinstance(table, str):
        table = f"{app}_{cls.name.lower()}"
    return DataModel(cls.name, table, "django", Location(entry_rel, cls.lineno), tuple(fields))


def _django(index: RepoIndex) -> list[DataModel]:
    models = []
    for entry in index.py_files:
        if entry.name != "models.py" and "/models/" not in f"/{entry.rel}":
            continue
        if "django" not in index.text(entry.rel):
            continue
        tree = pyast.parse_file(index, entry.rel)
        if tree is None:
            continue
        for cls in pyast.class_defs(tree):
            if any(b == "models.Model" or b.endswith("Model") for b in pyast.base_names(cls)):
                model = _django_model(entry.rel, cls)
                if model:
                    models.append(model)
    return models


def _sa_type(call: ast.Call, annotation: ast.expr | None) -> str:
    for arg in call.args:
        name = pyast.dotted(arg.func if isinstance(arg, ast.Call) else arg) or ""
        last = name.split(".")[-1]
        if last[:1].isupper() and last != "ForeignKey":
            return last
    return ast.unparse(annotation) if annotation is not None else ""


def _sqlalchemy(index: RepoIndex) -> list[DataModel]:
    models = []
    for entry in index.py_files:
        if "__tablename__" not in index.text(entry.rel):
            continue
        tree = pyast.parse_file(index, entry.rel)
        if tree is None:
            continue
        for cls in pyast.class_defs(tree):
            table = pyast.constant(pyast.assignments(cls.body).get("__tablename__"), None)
            if not isinstance(table, str):
                continue
            fields = []
            for stmt in cls.body:
                annotation = None
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                    target, value = stmt.targets[0], stmt.value
                elif isinstance(stmt, ast.AnnAssign):
                    target, value, annotation = stmt.target, stmt.value, stmt.annotation
                else:
                    continue
                if not isinstance(target, ast.Name) or not isinstance(value, ast.Call):
                    continue
                if not SA_COLUMN.match(pyast.dotted(value.func) or ""):
                    continue
                col_type = _sa_type(value, annotation)
                pk = pyast.constant(pyast.kwarg(value, "primary_key")) is True
                unique = pk or pyast.constant(pyast.kwarg(value, "unique")) is True
                auto = (pk and col_type in ("Integer", "BigInteger")) or (
                    pyast.constant(pyast.kwarg(value, "autoincrement")) is True)
                fields.append(Field(target.id, col_type, Location(entry.rel, stmt.lineno),
                                    unique, auto))
            models.append(DataModel(cls.name, table, "sqlalchemy",
                                    Location(entry.rel, cls.lineno), tuple(fields)))
    return models


def _drizzle_base_call(node):
    node = jsts.unwrap(node)
    while node is not None and node.type == "call_expression":
        fn = node.child_by_field_name("function")
        if fn is not None and fn.type == "member_expression":
            node = jsts.unwrap(fn.child_by_field_name("object"))
            continue
        return node
    return None


def _drizzle(index: RepoIndex) -> list[DataModel]:
    models = []
    for entry in index.js_files:
        text = index.text(entry.rel)
        if "drizzle" not in text or "Table(" not in text:
            continue
        for tree in jsts.parse_file(index, entry.rel):
            for call in jsts.calls(tree, DRIZZLE_TABLE):
                args = jsts.arguments(call)
                table = jsts.string_value(args[0]) if args else None
                if table is None or len(args) < 2:
                    continue
                fields = []
                for key, value in jsts.object_pairs(args[1]).items():
                    base = _drizzle_base_call(value)
                    if base is None:
                        continue
                    col_type = jsts.callee(base)
                    base_args = jsts.arguments(base)
                    column = jsts.string_value(base_args[0]) if base_args else None
                    chain = re.sub(r"\s+", "", jsts.node_text(value))
                    unique = ".unique(" in chain or ".primaryKey(" in chain
                    auto = col_type in ("serial", "bigserial", "smallserial") or any(
                        word in chain for word in (".autoincrement(", "AsIdentity("))
                    fields.append(Field(column or key, col_type,
                                        Location(entry.rel, jsts.line(tree, value)), unique, auto))
                models.append(DataModel(table, table, "drizzle",
                                        Location(entry.rel, jsts.line(tree, call)), tuple(fields)))
    return models


def extract_models(index: RepoIndex, state: SchemaState) -> list[DataModel]:
    models = _prisma(index)
    prisma_names = {m.table.lower() for m in models} | {m.name.lower() for m in models}
    models += [m for m in _sql(state) if m.name.lower() not in prisma_names]
    return models + _django(index) + _sqlalchemy(index) + _drizzle(index)


def find_model(models: list[DataModel], name: str) -> DataModel | None:
    wanted = name.lower()
    for model in models:
        candidates = {model.name.lower(), model.table.lower(), model.table.split(".")[-1].lower()}
        if wanted in candidates or wanted.rstrip("s") in {c.rstrip("s") for c in candidates}:
            return model
    return None
