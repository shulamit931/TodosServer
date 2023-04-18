
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using TodoApi;

var builder = WebApplication.CreateBuilder(args);


JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Name = "Authorization",
        Description = "Bearer Authentication with JWT Token",
        Type = SecuritySchemeType.Http
    });
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
        Reference = new OpenApiReference
                {
                    Id = "Bearer",
                    Type = ReferenceType.SecurityScheme
                }
            },
            new List<string>()
        }
    });
});
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["JWT:Issuer"],
            ValidAudience = builder.Configuration["JWT:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Key"]))
        };
    });
builder.Services.AddAuthorization();
builder.Services.AddCors(options =>
{
    options.AddPolicy("OpenPolicy",
                          policy =>
                          {
                              policy.WithOrigins("http://localhost:3000")
                                                  .AllowAnyHeader()
                                                  .AllowAnyMethod();
                          });
});
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddDbContext<ToDoDbContext>();

var app = builder.Build();
app.UseCors("OpenPolicy");

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}



app.UseAuthentication();

app.UseAuthorization();

IConfiguration _configuration = builder.Configuration;

//login
app.MapPost("/login", (ToDoDbContext db, LoginModel loginModel) =>
{
    if (db.Users.FirstOrDefault(u => u.Username == loginModel.UserName && u.Password == loginModel.Password) is User user)
    {
        var jwt = CreateJWT(user);
        return Results.Ok(jwt);
    }
    return Results.Unauthorized();
});

//register
app.MapPost("/register", async (ToDoDbContext db, LoginModel loginModel) =>
{
    if (db.Users?.FirstOrDefault(u => u.Username == loginModel.UserName) is User u)
    {
        return Results.Unauthorized();
    }
    var user = new User() { Password = loginModel?.Password, Username = loginModel?.UserName };
    db.Users?.AddAsync(user);
    await db.SaveChangesAsync();
    var jwt = CreateJWT(user);
    return Results.Ok(jwt);

});




//get all todos
app.MapGet("/items", [Authorize] async (ToDoDbContext db, HttpContext context) =>
{
    int.TryParse(context.User.Claims.FirstOrDefault(c => c.Type == "id")?.Value, out int userId);
    if (await db.Users.FindAsync(userId) is User user)
    {
        var list = db.Items.ToList().FindAll(i => i.UserId == user.Id);
        var result = new List<TodoModel>();
        foreach (var i in list)
        {
            result.Add(new TodoModel() { Name = i.Name, IsCompleted = i.IsCompleted, Id = i.Id });
        }
        return Results.Ok(result);
    }
    return Results.Forbid();
});
//get todo by id

app.MapGet("/items/{id}", [Authorize] async (ToDoDbContext db, int id, HttpContext context) =>
{
    int.TryParse(context.User.Claims.FirstOrDefault(c => c.Type == "id")?.Value, out int userId);
    if (await db.Users.FindAsync(userId) is User user)
    {
        if (await db.Items.FindAsync(id) is Item todo)
            if (todo.UserId == user.Id)
                return Results.Ok(new TodoModel() { Name = todo.Name, IsCompleted = todo.IsCompleted, Id = todo.Id });

    }
    return Results.Forbid();

});
//post a new todo
app.MapPost("/items", [Authorize] async (ToDoDbContext db, TodoModel todo, HttpContext context) =>
{
    int.TryParse(context.User.Claims.FirstOrDefault(c => c.Type == "id")?.Value, out int userId);
    if (await db.Users.FindAsync(userId) is User user)
    {
        db.Items.Add(new Item() { Name = todo.Name, IsCompleted = todo.IsCompleted, UserId = user.Id });
        await db.SaveChangesAsync();
        return Results.Created("/", todo);

    }
    return Results.Unauthorized();


});

//delete a todo 
app.MapDelete("/items/{id}", [Authorize] async (ToDoDbContext db, int id, HttpContext context) =>
{
    int.TryParse(context.User.Claims.FirstOrDefault(c => c.Type == "id")?.Value, out int userId);
    if (await db.Users.FindAsync(userId) is User user)
    {
        if (await db.Items.FindAsync(id) is Item todo)
        {
            if (todo.UserId == user.Id)
            {
                db.Items.Remove(todo);
                await db.SaveChangesAsync();
                return Results.Ok();
            }

        }
    }
    return Results.Forbid();
});

//update a todo
app.MapPut("/items/{id}", [Authorize] async (ToDoDbContext db, int id, TodoModel inputTodo, HttpContext context) =>
{
    int.TryParse(context.User.Claims.FirstOrDefault(c => c.Type == "id")?.Value, out int userId);
    if (await db.Users.FindAsync(userId) is User user)
    {
        if (await db.Items.FindAsync(id) is Item todo)
        {
            if (todo.UserId == user.Id)
            {
                todo.IsCompleted = inputTodo.IsCompleted;
                await db.SaveChangesAsync();
                return Results.Ok(new TodoModel(){Id=todo.Id,Name=todo.Name,IsCompleted=todo.IsCompleted});
            }
        }
    }
    return Results.Forbid();

});


object CreateJWT(User user)
{
    var claims = new List<Claim>()
                {
                    new Claim("id", user.Id.ToString()),
                    new Claim("name", user.Username)
                };

    var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetValue<string>("JWT:Key")));
    var signinCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);
    var tokeOptions = new JwtSecurityToken(
        issuer: _configuration.GetValue<string>("JWT:Issuer"),
        audience: _configuration.GetValue<string>("JWT:Audience"),
        claims: claims,
        expires: DateTime.Now.AddDays(30),
        signingCredentials: signinCredentials
    );
    var tokenString = new JwtSecurityTokenHandler().WriteToken(tokeOptions);
    return new { Token = tokenString };
}


app.Run();
