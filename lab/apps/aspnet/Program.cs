// ASP.NET Core minimal API lab app implementing the Labyrinth lab contract (see lab/README.md).
using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls($"http://0.0.0.0:{Environment.GetEnvironmentVariable("PORT") ?? "8000"}");
var app = builder.Build();
app.UseWebSockets();

var items = new[] { new { id = 1, name = "Widget" }, new { id = 2, name = "Gadget" } };
var sessions = new ConcurrentDictionary<string, string>();
string? User(HttpContext c) => c.Request.Cookies.TryGetValue("sid", out var s) && sessions.TryGetValue(s, out var u) ? u : null;

app.MapGet("/api/health", () => new { ok = true, framework = "aspnet" });
app.MapGet("/api/items", () => items);
app.MapGet("/api/items/{id:int}", (int id) => items.FirstOrDefault(i => i.id == id) is { } it
    ? Results.Ok(it) : Results.Json(new { error = "not found" }, statusCode: 404));
app.MapPost("/api/items", async (HttpRequest r) =>
{
    var body = await r.ReadFromJsonAsync<Dictionary<string, object>>() ?? new();
    body["id"] = 3;
    return Results.Json(body, statusCode: 201);
});
app.MapGet("/login", () => Results.Content("<form method=\"post\" action=\"/login\"><input name=\"username\"><input name=\"password\" type=\"password\"><button>Sign in</button></form>", "text/html"));
app.MapPost("/login", async (HttpContext c) =>
{
    var f = await c.Request.ReadFormAsync();
    if (f["username"] == "alice" && f["password"] == "wonderland")
    {
        var sid = Guid.NewGuid().ToString("N");
        sessions[sid] = "alice";
        c.Response.Cookies.Append("sid", sid, new CookieOptions { HttpOnly = true, SameSite = SameSiteMode.Lax });
        c.Response.Cookies.Append("theme", "dark");
        return Results.Redirect("/dashboard");
    }
    return Results.Text("invalid credentials", statusCode: 401);
});
app.MapGet("/dashboard", (HttpContext c) => User(c) is { } u
    ? Results.Content($"<h1>Welcome {u}</h1>", "text/html") : Results.Redirect("/login"));
app.MapPost("/checkout", (HttpContext c) => User(c) is not null
    ? Results.Ok(new { ok = true, order = 1001 }) : Results.Json(new { error = "login required" }, statusCode: 401));
app.MapPost("/upload", async (HttpRequest r) =>
{
    var f = await r.ReadFormAsync();
    return Results.Ok(new { size = f.Files.GetFile("file")?.Length ?? 0 });
});
app.MapGet("/redirect", () => Results.Redirect("/api/health"));
app.MapGet("/stream", async (HttpContext c) =>
{
    c.Response.ContentType = "text/event-stream";
    for (var n = 1; n <= 3; n++)
    {
        await c.Response.WriteAsync($"data: tick {n}\n\n");
        await c.Response.Body.FlushAsync();
        await Task.Delay(500);
    }
});
app.Map("/ws", async (HttpContext c) =>
{
    if (!c.WebSockets.IsWebSocketRequest) { c.Response.StatusCode = 400; return; }
    using var ws = await c.WebSockets.AcceptWebSocketAsync();
    var buf = new byte[4096];
    while (ws.State == WebSocketState.Open)
    {
        var res = await ws.ReceiveAsync(buf, CancellationToken.None);
        if (res.MessageType == WebSocketMessageType.Close) break;
        var reply = Encoding.UTF8.GetBytes("echo:" + Encoding.UTF8.GetString(buf, 0, res.Count));
        await ws.SendAsync(reply, WebSocketMessageType.Text, true, CancellationToken.None);
    }
});
app.Run();
