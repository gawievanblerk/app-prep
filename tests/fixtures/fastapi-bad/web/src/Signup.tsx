import { signup } from "./api"

export function SignupForm() {
  return <form onSubmit={(event) => signup(new FormData(event.currentTarget))} />
}
