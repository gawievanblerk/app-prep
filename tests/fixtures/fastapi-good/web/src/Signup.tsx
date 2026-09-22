import { register, signup } from "./api"

export function SignupForm() {
  return <form onSubmit={(event) => signup(new FormData(event.currentTarget))} />
}

export function InviteForm() {
  return <form onSubmit={(event) => register(new FormData(event.currentTarget))} />
}
