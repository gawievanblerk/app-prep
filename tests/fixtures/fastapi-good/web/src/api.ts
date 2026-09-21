export const signup = (body: unknown) =>
  fetch("/account/signup", { method: "POST", body: JSON.stringify(body) })
