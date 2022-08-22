using MinimalAPIWithJWT.Data;
using Microsoft.EntityFrameworkCore;
using MinimalAPIWithJWT.Models;
using MiniValidation;
using NetDevPack.Identity;
using NetDevPack.Identity.Jwt;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using NetDevPack.Identity.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.OpenApi.Models;

#region Configure Services

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();


builder.Services.AddDbContext<MinimalContextDB>(options => options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

//incluir para possibilitar o uso do NetDevPack na criação de JWT
builder.Services.AddIdentityEntityFrameworkContextConfiguration(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"),
    b => b.MigrationsAssembly("MinimalAPIWithJWT")));

builder.Services.AddIdentityConfiguration();
builder.Services.AddAuthentication();
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("ExcluirFornecedor", policy => policy.RequireClaim("ExcluirFornecedor"));
});    
builder.Services.AddAuthorizationCore();
builder.Services.AddJwtConfiguration(builder.Configuration, "AppSettings");

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Exemplo de Minimal API com JWT",
        Description = "Developed by Rodney Victor - ordabelem@gmail.com",
        Contact = new OpenApiContact { Name = "Rodney Victor", Email = "ordabelem@gmail.com" },
        License = new OpenApiLicense { Name = "MIT", Url = new Uri("https://opensource.org/licenses/MIT") }
    });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "Insira o token precedido da palavra Bearer. Ex: Bearer {token}",
        Name = "Authorization",
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[]{}
        }
    });
});

#endregion

#region Configure App

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthConfiguration(); //Configura o uso de autenticação
app.UseHttpsRedirection();

#endregion

#region Configure Endpoints

app.MapPost("/registro", [AllowAnonymous] async (
    SignInManager<IdentityUser> signInManager,
    UserManager<IdentityUser> userManager,
    IOptions<AppJwtSettings> appJwtSettings,
    RegisterUser registerUser) =>
{
    if (registerUser == null) return Results.BadRequest("Usuário não Identificado e ou Informado");
    if (!MiniValidator.TryValidate(registerUser, out var errors))
        return Results.ValidationProblem(errors);

    var user = new IdentityUser
    {
        UserName = registerUser.Email,
        Email = registerUser.Email,
        EmailConfirmed = true
    };

    var result = await userManager.CreateAsync(user, registerUser.Password);

    if(!result.Succeeded) return Results.BadRequest(result.Errors);

    var jwt = new JwtBuilder()
                    .WithUserManager(userManager)
                    .WithJwtSettings(appJwtSettings.Value)
                    .WithEmail(user.Email)
                    .WithJwtClaims()
                    .WithUserClaims()
                    .WithUserRoles()
                    .BuildUserResponse();

    return Results.Ok(jwt);

}).ProducesValidationProblem()
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status400BadRequest)
    .WithName("RegistroUsuario")
    .WithTags("Usuario");


app.MapPost("/login", [AllowAnonymous] async (
    SignInManager<IdentityUser> signInManager,
    UserManager<IdentityUser> userManager,
    IOptions<AppJwtSettings> appJwtSettings,
    LoginUser loginUser) =>
{
    if (loginUser == null) return Results.BadRequest("Usuário não Informado");
    if (!MiniValidator.TryValidate(loginUser, out var errors))
        return Results.ValidationProblem(errors);

    var result = await signInManager.PasswordSignInAsync(loginUser.Email, loginUser.Password,false,false);

    if (!result.Succeeded) return Results.BadRequest("Usuário ou senha inválidos");

    var jwt = new JwtBuilder()
                    .WithUserManager(userManager)
                    .WithJwtSettings(appJwtSettings.Value)
                    .WithEmail(loginUser.Email)
                    .WithJwtClaims()
                    .WithUserClaims()
                    .WithUserRoles()
                    .BuildUserResponse();

    return Results.Ok(jwt);

}).ProducesValidationProblem()
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status400BadRequest)
    .WithName("LoginUsuario")
    .WithTags("Usuario");


app.MapGet("/fornecedor", [AllowAnonymous] async (MinimalContextDB context) =>
    await context.Fornecedores.ToListAsync()
        is List<Fornecedor> fornecedores
        ? Results.Ok(fornecedores)
        :Results.NotFound("Não foram encontrados registros")
    )
    .Produces<List<Fornecedor>>(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status404NotFound)
    .WithName("GetFornecedor")
    .WithTags("Fornecedor");

app.MapGet("/fornecedor/{id}", [AllowAnonymous] async (
    Guid id,
    MinimalContextDB context) =>

    await context.Fornecedores.FindAsync(id)
        is Fornecedor fornecedor
        ? Results.Ok(fornecedor)
        : Results.NotFound("Não foram encontrados registros")
    
    )
    .Produces<Fornecedor>(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status404NotFound)
    .WithName("GetFornecedorPorId")
    .WithTags("Fornecedor");

app.MapPost("/fornecedor", [Authorize] async (
    MinimalContextDB context,
    Fornecedor fornecedor) =>
{
    if (!MiniValidator.TryValidate(fornecedor, out var errors))
        return Results.ValidationProblem(errors);

    context.Fornecedores.Add(fornecedor);
    var result = await context.SaveChangesAsync();

    return result > 0
    ? Results.Created($"/fornecedor/{fornecedor.Id}", fornecedor)
    : Results.BadRequest("Houve um erro ao salvar o fornecedor");
}
    )
    .ProducesValidationProblem()
    .Produces<Fornecedor>(StatusCodes.Status201Created)
    .Produces(StatusCodes.Status400BadRequest)
    .WithName("PostFornecedor")
    .WithTags("Fornecedor");



app.MapPut("/fornecedor/{id}", [Authorize] async (
    Guid id,
    MinimalContextDB context,
    Fornecedor fornecedor) =>
{
    var fornecedorB = await context.Fornecedores.AsNoTracking<Fornecedor>().FirstOrDefaultAsync(f => f.Id == id);
    if (fornecedorB == null) return Results.NotFound("Fornecedor não localizado na base");

    if (!MiniValidator.TryValidate(fornecedor, out var errors)) return Results.ValidationProblem(errors);

    context.Fornecedores.Update(fornecedor);
    var resultado = await context.SaveChangesAsync();

    return resultado > 0 ? Results.NoContent() : Results.BadRequest("Houve um erro ao atualizar o registro");
}
    )
    .ProducesValidationProblem()
    .Produces<Fornecedor>(StatusCodes.Status204NoContent)
    .Produces(StatusCodes.Status400BadRequest)
    .WithName("PutFornecedor")
    .WithTags("Fornecedor");


app.MapDelete("/fornecedor/{id}", [Authorize] async (
    Guid id,
    MinimalContextDB context) =>
{
    var fornecedorB = await context.Fornecedores.FindAsync(id);
    if (fornecedorB == null) return Results.NotFound("Fornecedor não localizado na base");

    context.Fornecedores.Remove(fornecedorB);
    var resultado = await context.SaveChangesAsync();

    return resultado > 0 ? Results.NoContent() : Results.BadRequest("Houve um erro ao deletar o registro");
}
    )
    .Produces(StatusCodes.Status400BadRequest)
    .Produces(StatusCodes.Status204NoContent)
    .Produces(StatusCodes.Status404NotFound)
    .RequireAuthorization("ExcluirFornecedor")
    .WithName("DeleteFornecedor")
    .WithTags("Fornecedor");

app.Run();

#endregion