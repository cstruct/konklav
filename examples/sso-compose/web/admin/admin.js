// The admin page's frontend. It holds no token and no key: its session is
// an HttpOnly cookie the backend set, and the backend does the rest.

const $ = (id) => document.getElementById(id);

async function call(method, path, body) {
  const response = await fetch(path, {
    method,
    headers: {
      // Required on writes: another site can't add it without a preflight.
      "x-example-admin": "1",
      ...(body ? { "content-type": "application/json" } : {}),
    },
    body: body && JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok) throw Object.assign(new Error(data.message), { status: response.status });
  return data;
}

function show(view) {
  $("status").hidden = true;
  for (const id of ["signed-out", "forbidden", "console"]) $(id).hidden = id !== view;
}

function button(label, className, action) {
  const element = document.createElement("button");
  element.textContent = label;
  if (className) element.className = className;
  element.addEventListener("click", async () => {
    element.disabled = true;
    try {
      await action();
      await renderUsers();
    } catch (error) {
      if (error.status === 401) return start();
      $("users-error").hidden = false;
      $("users-error").textContent = error.message;
    } finally {
      element.disabled = false;
    }
  });
  return element;
}

async function renderUsers() {
  $("users-error").hidden = true;
  const { users, roles } = await call("GET", "/api/users");
  $("users").replaceChildren(
    ...users.map((user) => {
      const row = document.createElement("tr");
      const who = document.createElement("td");
      who.textContent = user.emails.join(", ") || user.id;
      if (user.state !== "active") who.append(` (${user.state})`);

      const held = document.createElement("td");
      for (const role of roles) {
        const has = user.roles.includes(role);
        held.append(
          button(has ? `✓ ${role}` : `+ ${role}`, has ? "" : "secondary", () =>
            call(has ? "DELETE" : "PUT", `/api/users/${user.id}/roles/${role}`),
          ),
          " ",
        );
      }

      const actions = document.createElement("td");
      actions.append(
        button("Sign out everywhere", "danger", async () => {
          const { you } = await call("POST", `/api/users/${user.id}/sign-out`);
          if (you) location.reload();
        }),
        " ",
        user.state === "active"
          ? button("Disable", "danger", () => call("POST", `/api/users/${user.id}/disable`))
          : button("Enable", "secondary", () => call("POST", `/api/users/${user.id}/enable`)),
      );
      row.append(who, held, actions);
      return row;
    }),
  );
}

async function start() {
  try {
    const me = await call("GET", "/api/me");
    $("email").textContent = me.email;
    $("who").hidden = false;
    if (!me.admin) return show("forbidden");
    show("console");
    await renderUsers();
  } catch (error) {
    $("who").hidden = true;
    // Not signed in here: try single sign-on once, without a prompt.
    if (error.status === 401 && !returned) return location.assign("/login?silent");
    if (error.status === 401) return show("signed-out");
    $("status").hidden = false;
    $("status").textContent = error.message;
  }
}

$("sign-out").addEventListener("click", async () => {
  const { redirect } = await call("POST", "/logout");
  location.assign(redirect);
});

$("new-user").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("new-error").hidden = true;
  try {
    await call("POST", "/api/users", { email: $("new-email").value, password: $("new-password").value });
    $("new-user").reset();
    await renderUsers();
  } catch (error) {
    $("new-error").hidden = false;
    $("new-error").textContent = error.message;
  }
});

// Back from a silent attempt that found nobody signed in.
const returned = new URLSearchParams(location.search).has("error");
if (returned) history.replaceState(null, "", "/");
start();
