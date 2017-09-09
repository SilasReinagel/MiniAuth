using System;
using System.Data.SqlClient;
using System.Net;
using System.Configuration;
using Dapper;

private static string Json = "application/json";

public static async Task<HttpResponseMessage> Run(HttpRequestMessage req, TraceWriter log)
{
    var acc = await req.Content.ReadAsAsync<Account>();
    
    var reqIssues = GetRequestIssues(acc);
    if (reqIssues.Count > 0)
        return BadRequest(req, log, reqIssues);    
    if (!UsernameIsAvailable(acc.Username))
        return UsernameTaken(req, log, acc.Username);
    return SuccessResponse(req, log, acc);
}

private static List<string> GetRequestIssues(Account acc)
{
    var issues = new List<string>();
    if (acc.Username == null || acc.Username.Length == 0)
        issues.Add("Username required");
    if (acc.Password == null || acc.Password.Length == 0)
        issues.Add("Password required");
    return issues;
}

private static HttpResponseMessage UsernameTaken(HttpRequestMessage req, TraceWriter log, string userName)
{
    var msg = $"Username taken: '{userName}'";
    log.Error(msg);
    return req.CreateResponse(HttpStatusCode.Conflict, new { ErrorMessage = msg }, Json);
}

private static HttpResponseMessage BadRequest(HttpRequestMessage req, TraceWriter log, List<string> issues)
{
    var msg = string.Join(" AND ", issues);
    log.Error($"Invalid request errors: {msg}");
    return req.CreateResponse(HttpStatusCode.BadRequest, new { ErrorMessage = msg }, Json);
}

private static HttpResponseMessage SuccessResponse(HttpRequestMessage req, TraceWriter log, Account acc)
{
    var userId = SaveUser(acc);
    log.Info($"Created Account: Username={acc.Username}, UserId={userId}");
    return req.CreateResponse(HttpStatusCode.OK, new { UserID = userId }, Json);
}

private static bool UsernameIsAvailable(string username)
{
    using (var conn = CreateConnection())
        return conn.Query("SELECT UserId FROM Auth.Accounts WHERE Username = @username", new { username = username })
            .Count() == 0;
}

private static string SaveUser(Account acc)
{
    var userId = Guid.NewGuid().ToString();
    var encrypted = BCrypt.Net.BCrypt.HashPassword(acc.Password);

    using (var conn = CreateConnection())
        conn.Execute(@"INSERT INTO Auth.Accounts(UserId, Username, Password)
            VALUES(@userId, @username, @password)", 
                new { userId = userId, username = acc.Username, password = encrypted });
    
    return userId;
}

private static SqlConnection CreateConnection()
{
    return new SqlConnection(ConfigurationManager.ConnectionStrings["Auth"].ConnectionString);
}

private class Account
{
    public string Username { get; set; }
    public string Password { get; set; }
}
