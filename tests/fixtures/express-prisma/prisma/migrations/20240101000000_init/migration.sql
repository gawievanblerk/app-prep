CREATE TABLE "User" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "email" TEXT NOT NULL UNIQUE,
    "passwordHash" TEXT NOT NULL,
    "fullName" TEXT NOT NULL,
    "phone" TEXT,
    "resetToken" TEXT,
    "verifyToken" TEXT,
    "verified" BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE "Order" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "total" DECIMAL NOT NULL,
    "shippingAddress" TEXT NOT NULL
);

GRANT ALL ON ALL TABLES IN SCHEMA public TO app_user;
