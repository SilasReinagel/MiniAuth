using System;
using System.Configuration;
using System.Data.SqlClient;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Dapper;

private static string Json = "application/json";

public static async Task<HttpResponseMessage> Run(HttpRequestMessage req, TraceWriter log)
{
    var login = await req.Content.ReadAsAsync<AuthRequest>();
    var issues = GetAuthIssues(login);
    if (issues.Count > 0)
        return ErrorResponse(req, log, issues);
        
    var app = GetApp(login.AppName);
    if (!app.Exists)
        return ErrorResponse(req, log, new List<string> { $"Unknown App: {login.AppName}" });

    var result = Authorize(login);
    return result.IsAuthorized
        ? SuccessResponse(req, log, result, app.Secret)
        : UnauthorizedResponse(req, log, login);
}

private static List<string> GetAuthIssues(AuthRequest req)
{
    var issues = new List<string>();
    if (req.AppName == null || req.AppName.Length == 0)
        issues.Add("AppName required");
    if (req.Username == null || req.Username.Length == 0)
        issues.Add("Username required");
    if (req.Password == null || req.Password.Length == 0)
        issues.Add("Password required");
    return issues;
}

private static AuthResult Authorize(AuthRequest req)
{
    List<Account> accs;
    using (var conn = CreateConnection())
        accs = conn.Query<Account>(@"SELECT UserId, Username, Password FROM Auth.Accounts WHERE IsDisabled = 0 AND Username = @username",
            new { username = req.Username }).ToList();
    return accs.Count != 1 
        ? new AuthResult(false, "", req.Username)
        : new AuthResult(BCrypt.Net.BCrypt.Verify(req.Password, accs.Single().Password), accs.Single().UserId, req.Username);
}

private static AppResult GetApp(string appName)
{    
    List<App> apps;
    using (var conn = CreateConnection())
        apps = conn.Query<App>(@"SELECT Secret FROM Auth.Apps WHERE Name = @appName",
            new { appName }).ToList();
    return apps.Count != 1
        ? new AppResult()
        : new AppResult(apps.Single().Secret);
}

private static HttpResponseMessage ErrorResponse(HttpRequestMessage req, TraceWriter log, List<string> issues)
{
    var msg = string.Join(" AND ", issues);
    log.Error($"Invalid request errors: {msg}");
    return req.CreateResponse(HttpStatusCode.BadRequest, new { ErrorMessage = msg }, Json);
}

private static HttpResponseMessage UnauthorizedResponse(HttpRequestMessage req, TraceWriter log, AuthRequest auth)
{
    log.Error($"Invalid login attempt for {auth.Username}");
    return req.CreateResponse(HttpStatusCode.Unauthorized, new { ErrorMessage = "Invalid username or password." }, Json);
}

private static HttpResponseMessage SuccessResponse(HttpRequestMessage req, TraceWriter log, AuthResult result, string secret)
{
    log.Info($"Successful login for {result.UserId}");
    var expiration = GetExpirationTime();
    var token = Signed(secret, Payload(Header(), Claims(result.UserId, result.Username, expiration)));
    return req.CreateResponse(HttpStatusCode.OK, new AuthResponse(expiration, token), Json);
}

private static string GetExpirationTime()
{
    return DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds().ToString();
}

private static string Header()
{
    return "{\"typ\":\"JWT\",\"alg\":\"HS256\"}";
}

private static string Claims(string userId, string username, string expiresAtUtc)
{
    return $"{{\"sub\":\"{userId}\", \"exp\": {expiresAtUtc}, \"username\": \"{username}\"}}";
}

private static string Payload(string headerJson, string claimsJson)
{
    return Base64UrlEncode(headerJson) + "." + Base64UrlEncode(claimsJson);
}

private static string Signed(string key, string payload)
{
    return payload + "." + Base64UrlEncode(HMAC256(Bytes(key), Bytes(payload)));
}

private static byte[] Bytes(string src)
{
    return Encoding.UTF8.GetBytes(src);
}

private static string UTF8(byte[] bytes)
{
    return Encoding.UTF8.GetString(bytes);
}

private static string Base64UrlEncode(string src)
{
	return Base64UrlEncode(Bytes(src));
}

private static string Base64UrlEncode(byte[] bytes)
{
	return Convert.ToBase64String(bytes)
		.Replace('+', '-')
		.Replace('/', '_')
		.Replace("=", "");
}

private static byte[] HMAC256(byte[] key, byte[] message)
{
    var hmac = new HMACSHA256(key);
    var hash = hmac.ComputeHash(message);
    return hash;
}

private static SqlConnection CreateConnection()
{
    return new SqlConnection(ConfigurationManager.ConnectionStrings["Auth"].ConnectionString);
}

private class AuthRequest
{
    public string AppName { get; set; }
    public string Username { get; set; }
    public string Password { get; set; }
}

private class Account
{
    public string UserId { get; set; }
    public string Username { get; set; }
    public string Password { get; set; }
}

private class App
{
    public string Secret { get; set; }
}

private class AppResult 
{
    public bool Exists { get; private set; }
    public string Secret { get; private set; }

    public AppResult()
    {
        Exists = false;
        Secret = "";
    }

    public AppResult(string secret)
    {
        Exists = true;
        Secret = secret;
    }
}

private class AuthResult
{
    public bool IsAuthorized { get; private set; }
    public string UserId { get; private set; }
    public string Username { get; private set; }

    public AuthResult(bool isAuthorized, string userId, string username)
    {
        IsAuthorized = isAuthorized;
        UserId = userId;
        Username = username;
    }
}

private class AuthResponse
{
    public string ExpiresAtUtc { get; private set; }
    public string Token { get; private set; }

    public AuthResponse(string expiresAtUtc, string token)
    {
        ExpiresAtUtc = expiresAtUtc;
        Token = token;
    }
}
