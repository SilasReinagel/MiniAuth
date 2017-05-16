using System;
using System.Data.SqlClient;
using System.Net;
using System.Configuration;
using System.Linq;
using Dapper;

private static string Json = "application/json";

public static async Task<HttpResponseMessage> Run(HttpRequestMessage req, TraceWriter log)
{
    var login = await req.Content.ReadAsAsync<AuthRequest>();
    var issues = GetAuthIssues(login);
    if (issues.Count > 0)
        return ErrorResponse(req, log, issues);

    var result = Authorize(login);
    return result.IsAuthorized
        ? SuccessResponse(req, log, result)
        : UnauthorizedResponse(req, log, login);
}

private static List<string> GetAuthIssues(AuthRequest req)
{
    var issues = new List<string>();
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
        ? new AuthResult(false, "")
        : new AuthResult(BCrypt.Net.BCrypt.Verify(req.Password, accs.Single().Password), accs.Single().UserId);
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

private static HttpResponseMessage SuccessResponse(HttpRequestMessage req, TraceWriter log, AuthResult result)
{
    log.Info($"Successful login for {result.UserId}");
    return req.CreateResponse(HttpStatusCode.OK, new { UserID = result.UserId }, Json);
}

private static SqlConnection CreateConnection()
{
    return new SqlConnection(ConfigurationManager.ConnectionStrings["Auth"].ConnectionString);
}

private class AuthRequest
{
    public string Username { get; set; }
    public string Password { get; set; }
}

private class Account
{
    public string UserId { get; set; }
    public string Username { get; set; }
    public string Password { get; set; }
}

private class AuthResult
{
    public string UserId { get; private set; }
    public bool IsAuthorized { get; private set; }

    public AuthResult(bool isAuthorized, string userId)
    {
        IsAuthorized = isAuthorized;
        UserId = userId;
    }
}
