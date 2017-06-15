using System;
using System.Data.SqlClient;
using System.Net;
using System.Configuration;
using Dapper;

private static string Json = "application/json";

public static async Task<HttpResponseMessage> Run(HttpRequestMessage req, TraceWriter log)
{
    var app = await req.Content.ReadAsAsync<App>();
    
    var issues = GetAppIssues(app);    
    return issues.Count > 0 
        ? ErrorResponse(req, log, issues)
        : SuccessResponse(req, log, app);
}

private static List<string> GetAppIssues(App app)
{
    var issues = new List<string>();
    if (app.Name == null || app.Name.Length == 0)
        issues.Add("Name required");
    if (!NameIsAvailable(app.Name))
        issues.Add("That app name is already taken");
    if (app.Secret == null || app.Secret.Length == 0)
        issues.Add("Secret required");
    return issues;
}

private static HttpResponseMessage ErrorResponse(HttpRequestMessage req, TraceWriter log, List<string> issues)
{
    var msg = string.Join(" AND ", issues);
    log.Error($"Invalid request errors: {msg}");
    return req.CreateResponse(HttpStatusCode.BadRequest, new { ErrorMessage = msg }, Json);
}

private static HttpResponseMessage SuccessResponse(HttpRequestMessage req, TraceWriter log, App app)
{
    SaveApp(app);
    log.Info($"Registered App: Name={app.Name}");
    return req.CreateResponse(HttpStatusCode.OK, new { AppName = app.Name }, Json);
}

private static bool NameIsAvailable(string name)
{
    using (var conn = CreateConnection())
        return conn.Query("SELECT Name FROM Auth.Apps WHERE Name = @name", new { name = name })
            .Count() == 0;
}

private static void SaveApp(App app)
{
    using (var conn = CreateConnection())
        conn.Execute(@"INSERT INTO Auth.Apps(Name, Secret)
            VALUES(@name, @secret)", 
                new { name = app.Name, secret = app.Secret });
}

private static SqlConnection CreateConnection()
{
    return new SqlConnection(ConfigurationManager.ConnectionStrings["Auth"].ConnectionString);
}

private class App
{
	public string Name { get; set; }
	public string Secret { get; set; }
}
