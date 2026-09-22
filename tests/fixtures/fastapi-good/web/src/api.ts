export const signup = (body: unknown) =>
  fetch("/account/signup", { method: "POST", body: JSON.stringify(body) })

export const register = (body: unknown) =>
  fetch("/auth/register", { method: "POST", body: JSON.stringify(body) })
