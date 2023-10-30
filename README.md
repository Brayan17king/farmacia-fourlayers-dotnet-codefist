# **Veterinaria CodeFirst**

- Creación de Proyecto
  1. [Creación de sln](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#Creacion-de-sln)
  2. [Creación de proyectos de classlib](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#Creacion-de-proyectos-classlib)
  3. [Creación de proyecto de webapi](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#Creacion-de-proyecto-webapi)
  4. [Agregar proyectos al sln](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#Agregar-proyectos-al-sln)
  5. [Agregar referencia entre proyectos](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#Agregar-referencia-entre-proyectos)
- Instalación de paquetes
  1. [Proyecto API](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#Proyecto-API)
  2. [Proyecto Domain](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#Proyecto-Domain)
  3. [Proyecto Persistance](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#Proyecto-Persistance)
- Migración de Proyecto
  1. [Migración](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#Migracion)
  2. [Actualizar base de datos](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#Actualizar-base-de-datos)
- API
  1. Controllers
     - [EntityController.cs](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#EntityController)
     - [BaseController.cs](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#BaseController)
     - [UserController.cs](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#UserController)
  2. Dtos
     - [EntityDto.cs](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#EntityDto)
  3. Extensions
     - [ApplicationServicesExtension.cs](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#ApplicationServicesExtension)
  4. Helper
     - [Authorization.cs](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#Authorization)
     - [JWT.cs](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#JWT)
     - [Pager.cs](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#Pager)
     - [Params.cs](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#Params)
  5. Profiles
     - [MappingProfiles.cs](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#MappingProfiles)
  6. Program
     - [Program.cs](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#Program)
  7. Services
     - [UserService.cs](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#UserService)
     - [IUserService.cs](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#IUserService)
- Application
  1. Repositories
     - [EntityRepository.cs](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#EntityRepository)
     - [GenericRepository.cs](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#GenericRepository)
  2. UnitOfWork
     - [UnitOfWork.cs](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#UnitOfWork)
- Domain
  1. Entities
     - [Entity.cs](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#Entity)
     - [BaseEntity.cs](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#BaseEntity)
  2. Interfaces
     - [IEntity.cs](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#IEntity)
     - [IUser.cs](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#IUser)
     - [IGenericRepository.cs](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#IGenericRepository)
     - [IUnitOfWork.cs](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#IUnitOfWork)
- Persistance
  1. Data
     - Configuration
       - [EntityConfiguration.cs](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#EntityConfiguration)
     - [DbContext.cs](https://file+.vscode-resource.vscode-cdn.net/c%3A/Users/lenin/OneDrive/Documentos/campus/dotnet/veterinaria-fourlayers/README.md#DbContext)

## Creación de proyecto

#### Creacion de sln

```
dotnet new sln
```

#### Creacion de proyectos classlib

```
dotnet new classlib -o Application
dotnet new classlib -o Domain
dotnet new classlib -o Persistance
```

#### Creacion de proyecto webapi

```
dotnet new webapi -o API
```

#### Agregar proyectos al sln

```
dotnet sln add API
dotnet sln add Application
dotnet sln add Domain
dotnet sln add Persistance
```

#### Agregar referencia entre proyectos

```
cd ./API/
dotnet add reference ../Application/
cd ..
cd ./Application/
dotnet add reference ../Domain/
dotnet add reference ../Persistence/
cd ..
cd ./Persistance/
dotnet add reference ../Domain/
```

## Instalacion de paquetes

#### Proyecto API

```
dotnet add package AspNetCoreRateLimit
dotnet add package AutoMapper.Extensions.Microsoft.DependencyInjection
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package Microsoft.AspNetCore.Mvc.Versioning
dotnet add package Microsoft.AspNetCore.OpenApi
dotnet add package Microsoft.EntityFrameworkCore.Design
dotnet add package System.IdentityModel.Tokens.Jwt
dotnet add package Serilog.AspNetCore
dotnet add package Microsoft.Extensions.DependencyInjection
dotnet add package Microsoft.EntityFrameworkCore
```

#### Proyecto Domain

```
dotnet add package FluentValidation.AspNetCore
dotnet add package itext7.pdfhtml
dotnet add package Microsoft.EntityFrameworkCore
```

#### Proyecto Persistance

```
dotnet add package Microsoft.EntityFrameworkCore
dotnet add package Pomelo.EntityFrameworkCore.MySql
```

## Migración de Proyecto

#### Migracion

```
dotnet ef migrations add InitialCreate --project ./Persistance/ --startup-project ./API/ --output-dir ./Data/Migrations
```

#### Actualizar base de datos

```
dotnet ef database update --project ./Persistance/ --startup-project ./API/     
```

## API

#### Controllers

###### CiudadController

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using API.Dtos;
using AutoMapper;
using Domain.Entities;
using Domain.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers;

public class CiudadController : BaseController
{
    private readonly IUnitOfWork _unitOfWork;
    private readonly IMapper _mapper;

    public CiudadController(IUnitOfWork unitOfWork, IMapper mapper)
    {
        _unitOfWork = unitOfWork;
        _mapper = mapper;
    }

    [HttpGet]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<IEnumerable<CiudadDto>>> Get()
    {
        var result = await _unitOfWork.Ciudades.GetAllAsync();
        return _mapper.Map<List<CiudadDto>>(result);
    }

    [HttpGet("{id}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<CiudadDto>> Get(int id)
    {
        var result = await _unitOfWork.Ciudades.GetByIdAsync(id);
        if (result == null)
        {
            return NotFound();
        }
        return _mapper.Map<CiudadDto>(result);
    }

    [HttpPost]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<CiudadDto>> Post(CiudadDto resultDto)
    {
        var result = _mapper.Map<Ciudad>(resultDto);
        _unitOfWork.Ciudades.Add(result);
        await _unitOfWork.SaveAsync();
        if (result == null)
        {
            return BadRequest();
        }
        resultDto.Id = result.Id;
        return CreatedAtAction(nameof(Post), new { id = resultDto.Id }, resultDto);
    }

    [HttpPut("{id}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<CiudadDto>> Put(int id, [FromBody] CiudadDto resultDto)
    {
        if (resultDto.Id == 0)
        {
            resultDto.Id = id;
        }
        if (resultDto.Id != id)
        {
            return NotFound();
        }
        var result = _mapper.Map<Ciudad>(resultDto);
        resultDto.Id = result.Id;
        _unitOfWork.Ciudades.Update(result);
        await _unitOfWork.SaveAsync();
        return resultDto;
    }

    [HttpDelete("{id}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Delete(int id)
    {
        var result = await _unitOfWork.Ciudades.GetByIdAsync(id);
        if (result == null)
        {
            return NotFound();
        }
        _unitOfWork.Ciudades.Remove(result);
        await _unitOfWork.SaveAsync();
        return NoContent();
    }
}
```

###### BaseController

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class BaseController : ControllerBase
{

}
```

###### UserController

```csharp
using API.Dtos;
using API.Services;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers;

public class UserController : BaseController
{
    private readonly IUserService _userService;

    public UserController(IUserService userService)
    {
        _userService = userService;
    }

    [HttpPost("register")]
    public async Task<ActionResult> RegisterAsync(RegisterDto model)
    {
        var result = await _userService.RegisterAsync(model);
        return Ok(result);
    }

    [HttpPost("token")]
    public async Task<ActionResult> GetTokenAsync(LoginDto model)
    {
        var result = await _userService.GetTokenAsync(model);
        SetRefreshTokenInCookie(result.RefreshToken);
        return Ok(result);
    }

    [HttpPost("addrol")]
    public async Task<ActionResult> AddRolAsync(AddRolDto model)
    {
        var result = await _userService.AddRolAsync(model);
        return Ok(result);
    }

    [HttpPost("refresh-token")]
    public async Task<ActionResult> RefreshToken()
    {
        var refreshToken = Request.Cookies["refreshToken"];
        var result = await _userService.RefreshTokenAsync(refreshToken);
        if (!string.IsNullOrEmpty(result.RefreshToken))
        {
            SetRefreshTokenInCookie(result.RefreshToken);
        }
        return Ok(result);
    }

    private void SetRefreshTokenInCookie(string refreshToken)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Expires = DateTime.UtcNow.AddDays(2),
        };
        Response.Cookies.Append("refreshToken", refreshToken, cookieOptions);
    }
}


```

#### Dtos

###### CiudadDto

```csharp
namespace API.Dtos;

public class CiudadDto
{
    public int Id { get; set; }
    public string NombreCiudad { get; set; }
    public int IdDepartamentoFk { get; set; }
}
```

#### Extensions

###### ApplicationServicesExtension

```csharp
using AspNetCoreRateLimit;
using Domain.Interfaces;
using Application.UnitOfWork;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using API.Helpers;

namespace API.Extensions;

public static class ApplicationServiceExtensions
{
    public static void ConfigureCors(this IServiceCollection services) => services.AddCors(options =>
    {
        options.AddPolicy("CorsPolicy", builder =>
        {
            builder.AllowAnyOrigin() // WithOrigins("https://domain.com")
            .AllowAnyMethod() // WithMethods("GET", "POST")
            .AllowAnyHeader(); // WithHeaders("accept", "content-type")
        });
    }); // Remember to put 'static' on the class and to add builder.Services.ConfigureCors(); and app.UseCors("CorsPolicy"); to Program.cs

    public static void ConfigureRateLimiting(this IServiceCollection services)
    {
        services.AddMemoryCache();
        services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();
        services.AddInMemoryRateLimiting();
        services.Configure<IpRateLimitOptions>(options =>
        {
            options.EnableEndpointRateLimiting = true;
            options.StackBlockedRequests = false;
            options.HttpStatusCode = 429;
            options.RealIpHeader = "X-Real-IP";
            options.GeneralRules = new List<RateLimitRule>
            {
                new RateLimitRule
                {
                    Endpoint = "*",  // Si quiere usar todos ponga *
                    Period = "10s", // Periodo de tiempo para hacer peticiones
                    Limit = 2         // Numero de peticiones durante el periodo de tiempo
                }
            };
        });
    } // Remember adding builder.Services.ConfigureRateLimiting(); and builder.Services.AddAutoMapper(Assembly.GetEntryAssembly()); and app.UseIpRateLimiting(); to Program.cs

    public static void AddApplicationServices(this IServiceCollection services)
    {
        services.AddScoped<IUnitOfWork, UnitOfWork>();
    } // Remember to add builder.Services.AddApplicationServices(); to Program.cs

    public static void AddJwt(this IServiceCollection services, IConfiguration configuration)
    {
        // Configuration from AppSettings
        services.Configure<JWT>(configuration.GetSection("JWT"));

        // Adding Authentication - JWT
        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(o =>
        {
            o.RequireHttpsMetadata = false;
            o.SaveToken = false;
            o.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                ValidIssuer = configuration["JWT:Issuer"],
                ValidAudience = configuration["JWT:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Key"]))
            };
        });
    }
}
```

#### Helpers

###### Authorization

```csharp
namespace API.Helpers
{
    public class Authorization
    {
        public enum Roles
        {
            Administrator,
            Manager,
            Employee,
            Person
        }

        public const Roles rol_default = Roles.Person;
    }
}
```

###### 

###### JWT

```csharp
namespace API.Helpers;

public class JWT
{
    public string Key { get; set; }
    public string Issuer { get; set; }
    public string Audience { get; set; }
    public double DurationInMinutes { get; set; }
}
```

###### Pager

```csharp
namespace API.Helpers;

public class Pager<T> where T : class
    {
    public string Search { get; set; }
    public int PageIndex { get; set; }
    public int PageSize { get; set; }
    public int Total { get; set; }
    public List<T> Registers { get; private set; }

    public Pager()
    {
    }

    public Pager(List<T> registers, int total, int pageIndex, int pageSize, string search)
    {
        Registers = registers;
        Total = total;
        PageIndex = pageIndex;
        PageSize = pageSize;
        Search = search;
    }

    public int TotalPages
    {
        get { return (int)Math.Ceiling(Total / (double)PageSize); }
        set { this.TotalPages = value; }
    }

    public bool HasPreviousPage
    {
        get { return (PageIndex > 1); }
        set { this.HasPreviousPage = value; }
    }

    public bool HasNextPage
    {
        get { return (PageIndex < TotalPages); }
        set { this.HasNextPage = value; }
    }
}
```

###### Params

```csharp
namespace API.Helpers;

public class Params
{
    private int _pageSize = 5;
    private const int MaxPageSize = 50;
    private int _pageIndex = 1;
    private string _search;

    public int PageSize
    {
        get => _pageSize;
        set => _pageSize = (value > MaxPageSize) ? MaxPageSize : value;
    }

    public int PageIndex
    {
        get => _pageIndex;
        set => _pageIndex = (value <= 0) ? 1 : value;
    }

    public string Search
    {
        get => _search;
        set => _search = (!String.IsNullOrEmpty(value)) ? value.ToLower() : "";
    }
}
```

#### Profiles

###### MappingProfiles

```csharp
using API.Dtos;
using AutoMapper;
using Domain.Entities;

namespace API.Profiles;

public class MappingProfiles : Profile
{
    public MappingProfiles()
    {
        CreateMap<Ciudad,CiudadDto>().ReverseMap();
        ...
    }
}
```

#### Program

###### Program

```csharp
using System.Reflection;
using API.Extensions;
using AspNetCoreRateLimit;
using Persistance.Data;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

builder.Services.AddDbContext<VeterinariaContext>(optionsBuilder =>
{
    string connectionString = builder.Configuration.GetConnectionString("MySqlConex");
    optionsBuilder.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString));
});

builder.Services.ConfigureCors();

builder.Services.ConfigureRateLimiting();

builder.Services.AddAutoMapper(Assembly.GetEntryAssembly());

builder.Services.AddApplicationServices();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors("CorsPolicy");

app.UseIpRateLimiting();

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
```

## Application

#### Repositories

###### CiudadRepository

```csharp
using Domain.Entities;
using Domain.Interfaces;
using Persistance.Data;
using Microsoft.EntityFrameworkCore;

namespace Application.Repositories;

public class CiudadRepository : GenericRepository<Ciudad>,ICiudadRepository
{
    private readonly FarmaciaFourLayersContext _context;

    public CiudadRepository(FarmaciaFourLayersContext context) : base(context)
    {
        _context = context;
    }

    public override async Task<IEnumerable<Ciudad>> GetAllAsync()
    {
        return await _context.Ciudades
                    .Include(c => c.UbicacionPersonas)
                    .ToListAsync();
    }

    public override async Task<(int totalRegistros, IEnumerable<Ciudad> registros)> GetAllAsync(
        int pageIndex,
        int pageSize,
        string search
    )
    {
        var query = _context.Ciudades as IQueryable<Ciudad>;
    
        if (!string.IsNullOrEmpty(search))
        {
            query = query.Where(p => p.NombreCiudad.ToLower().Contains(search)); // If necesary add .ToString() after varQuery
        }
        query = query.OrderBy(p => p.Id);
    
        var totalRegistros = await query.CountAsync();
        var registros = await query
                        .Include(p => p.UbicacionPersonas)
                        .Skip((pageIndex - 1) * pageSize)
                        .Take(pageSize)
                        .ToListAsync();
        return (totalRegistros, registros);
    }
}
```

###### GenericRepository

```csharp
using System.Linq.Expressions;
using Domain.Entities;
using Domain.Interfaces;
using Persistance.Data;
using Microsoft.EntityFrameworkCore;

namespace Application.Repositories;

public class GenericRepository<T> : IGenericRepository<T> where T : BaseEntity
{
    private readonly FarmaciaFourLayersContext _context;

    public GenericRepository(FarmaciaFourLayersContext context)
    {
        _context = context;
    }

    public virtual void Add(T entity)
    {
        _context.Set<T>().Add(entity);
    }

    public virtual void AddRange(IEnumerable<T> entities)
    {
        _context.Set<T>().AddRange(entities);
    }

    public virtual IEnumerable<T> Find(Expression<Func<T, bool>> expression)
    {
        return _context.Set<T>().Where(expression);
    }

    public virtual async Task<IEnumerable<T>> GetAllAsync()
    {
        return await _context.Set<T>().ToListAsync();
        // return (IEnumerable<T>) await _context.Entities.FromSqlRaw("SELECT * FROM entity").ToListAsync();
    }

    public virtual async Task<T> GetByIdAsync(int id)
    {
        return await _context.Set<T>().FindAsync(id);
    }

    public virtual void Remove(T entity)
    {
        _context.Set<T>().Remove(entity);
    }

    public virtual void RemoveRange(IEnumerable<T> entities)
    {
        _context.Set<T>().RemoveRange(entities);
    }

    public virtual void Update(T entity)
    {
        _context.Set<T>().Update(entity);
    }
    public virtual async Task<(int totalRegistros, IEnumerable<T> registros)> GetAllAsync(
        int pageIndex,
        int pageSize,
        string _search
    )
    {
        var totalRegistros = await _context.Set<T>().CountAsync();
        var registros = await _context
            .Set<T>()
            .Skip((pageIndex - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();
        return (totalRegistros, registros);
    }
}
```

###### GenericRepositoryVC

```csharp
using System.Linq.Expressions;
using Domain.Entities;
using Domain.Interfaces;
using Persistance.Data;
using Microsoft.EntityFrameworkCore;

namespace Application.Repositories;

public class GenericRepositoryVC<T> : IGenericRepositoryVC<T> where T : BaseEntityVC
{
    private readonly FarmaciaFourLayersContext _context;

    public GenericRepositoryVC(FarmaciaFourLayersContext context)
    {
        _context = context;
    }

    public virtual void Add(T entity)
    {
        _context.Set<T>().Add(entity);
    }

    public virtual void AddRange(IEnumerable<T> entities)
    {
        _context.Set<T>().AddRange(entities);
    }

    public virtual IEnumerable<T> Find(Expression<Func<T, bool>> expression)
    {
        return _context.Set<T>().Where(expression);
    }

    public virtual async Task<IEnumerable<T>> GetAllAsync()
    {
        return await _context.Set<T>().ToListAsync();
        // return (IEnumerable<T>) await _context.Entities.FromSqlRaw("SELECT * FROM entity").ToListAsync();
    }

    public virtual async Task<T> GetByIdAsync(string id)
    {
        return await _context.Set<T>().FindAsync(id);
    }

    public virtual void Remove(T entity)
    {
        _context.Set<T>().Remove(entity);
    }

    public virtual void RemoveRange(IEnumerable<T> entities)
    {
        _context.Set<T>().RemoveRange(entities);
    }

    public virtual void Update(T entity)
    {
        _context.Set<T>().Update(entity);
    }
    public virtual async Task<(int totalRegistros, IEnumerable<T> registros)> GetAllAsync(
        int pageIndex,
        int pageSize,
        string _search
    )
    {
        var totalRegistros = await _context.Set<T>().CountAsync();
        var registros = await _context
            .Set<T>()
            .Skip((pageIndex - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();
        return (totalRegistros, registros);
    }
}
```

#### UnitOfWork

###### UnitOfWork

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Domain.Interfaces;
using Persistance.Data;
using Application.Repositories;

namespace Application.UnitOfWork;

public class UnitOfWork : IUnitOfWork,IDisposable
{
    private readonly FarmaciaFourLayersContext _context;
    private ICiudadRepository _Ciudades;
    private IContactoPersonaRepository _ContactoPersonas;
    private IDepartamentoRepository _Departamentos;
    private IDetalleMovimientoInventarioRepository _DetalleMovimientoInventarios;
    private IFacturaRepository _Facturas;
    private IFormaPagoRepository _FormaPagos;
    private IInventarioRepository _Inventarios;
    private IMarcaRepository _Marcas;
    private IMovimientoInventarioRepository _MovimientoInventarios;
    private IPaisRepository _Paises;
    private IPersonaRepository _Personas;
    private IPresentacionRepository _Presentaciones;
    private IProductoRepository _Productos;
    private IRolPersonaRepository _RolPersonas;
    private ITipoContactoRepository _TipoContactos;
    private ITipoDocumentoRepository _TipoDocumentos;
    private ITipoMovimientoInventarioRepository _TipoMovimientoInventarios;
    private ITipoPersonaRepository _TipoPersonas;
    private IUbicacionPersonaRepository _UbicacionPersonas;
    private IUserRepository _Users;
    private IRolRepository _Rols;
    private IRefreshTokenRepository _RefreshTokens;

    public UnitOfWork(FarmaciaFourLayersContext context)
    {
        _context = context;
    }

    public ICiudadRepository Ciudades
    {
        get
        {
            if (_Ciudades == null)
            {
                _Ciudades = new CiudadRepository (_context); // Remember putting the base in the repository of this entity
            }
            return _Ciudades;
        }
    }
    public IContactoPersonaRepository ContactoPersonas
    {
        get
        {
            if (_ContactoPersonas == null)
            {
                _ContactoPersonas = new ContactoPersonaRepository (_context); // Remember putting the base in the repository of this entity
            }
            return _ContactoPersonas;
        }
    }
    public IDepartamentoRepository Departamentos
    {
        get
        {
            if (_Departamentos == null)
            {
                _Departamentos = new DepartamentoRepository (_context); // Remember putting the base in the repository of this entity
            }
            return _Departamentos;
        }
    }
    public IDetalleMovimientoInventarioRepository DetalleMovimientoInventarios
    {
        get
        {
            if (_DetalleMovimientoInventarios == null)
            {
                _DetalleMovimientoInventarios = new DetalleMovimientoInventarioRepository (_context); // Remember putting the base in the repository of this entity
            }
            return _DetalleMovimientoInventarios;
        }
    }
    public IFacturaRepository Facturas
    {
        get
        {
            if (_Facturas == null)
            {
                _Facturas = new FacturaRepository (_context); // Remember putting the base in the repository of this entity
            }
            return _Facturas;
        }
    }
    public IFormaPagoRepository FormaPagos
    {
        get
        {
            if (_FormaPagos == null)
            {
                _FormaPagos = new FormaPagoRepository (_context); // Remember putting the base in the repository of this entity
            }
            return _FormaPagos;
        }
    }
    public IInventarioRepository Inventarios
    {
        get
        {
            if (_Inventarios == null)
            {
                _Inventarios = new InventarioRepository (_context); // Remember putting the base in the repository of this entity
            }
            return _Inventarios;
        }
    }
    public IMarcaRepository Marcas
    {
        get
        {
            if (_Marcas == null)
            {
                _Marcas = new MarcaRepository (_context); // Remember putting the base in the repository of this entity
            }
            return _Marcas;
        }
    }
    public IMovimientoInventarioRepository MovimientoInventarios
    {
        get
        {
            if (_MovimientoInventarios == null)
            {
                _MovimientoInventarios = new MovimientoInventarioRepository (_context); // Remember putting the base in the repository of this entity
            }
            return _MovimientoInventarios;
        }
    }
    public IPaisRepository Paises
    {
        get
        {
            if (_Paises == null)
            {
                _Paises = new PaisRepository (_context); // Remember putting the base in the repository of this entity
            }
            return _Paises;
        }
    }
    public IPersonaRepository Personas
    {
        get
        {
            if (_Personas == null)
            {
                _Personas = new PersonaRepository (_context); // Remember putting the base in the repository of this entity
            }
            return _Personas;
        }
    }
    public IPresentacionRepository Presentaciones
    {
        get
        {
            if (_Presentaciones == null)
            {
                _Presentaciones = new PresentacionRepository (_context); // Remember putting the base in the repository of this entity
            }
            return _Presentaciones;
        }
    }
    public IProductoRepository Productos
    {
        get
        {
            if (_Productos == null)
            {
                _Productos = new ProductoRepository (_context); // Remember putting the base in the repository of this entity
            }
            return _Productos;
        }
    }
    public IRolPersonaRepository RolPersonas
    {
        get
        {
            if (_RolPersonas == null)
            {
                _RolPersonas = new RolPersonaRepository (_context); // Remember putting the base in the repository of this entity
            }
            return _RolPersonas;
        }
    }
    public ITipoContactoRepository TipoContactos
    {
        get
        {
            if (_TipoContactos == null)
            {
                _TipoContactos = new TipoContactoRepository (_context); // Remember putting the base in the repository of this entity
            }
            return _TipoContactos;
        }
    }
    public ITipoDocumentoRepository TipoDocumentos
    {
        get
        {
            if (_TipoDocumentos == null)
            {
                _TipoDocumentos = new TipoDocumentoRepository (_context); // Remember putting the base in the repository of this entity
            }
            return _TipoDocumentos;
        }
    }
    public ITipoMovimientoInventarioRepository TipoMovimientoInventarios
    {
        get
        {
            if (_TipoMovimientoInventarios == null)
            {
                _TipoMovimientoInventarios = new TipoMovimientoInventarioRepository (_context); // Remember putting the base in the repository of this entity
            }
            return _TipoMovimientoInventarios;
        }
    }
    public ITipoPersonaRepository TipoPersonas
    {
        get
        {
            if (_TipoPersonas == null)
            {
                _TipoPersonas = new TipoPersonaRepository (_context); // Remember putting the base in the repository of this entity
            }
            return _TipoPersonas;
        }
    }
    public IUbicacionPersonaRepository UbicacionPersonas
    {
        get
        {
            if (_UbicacionPersonas == null)
            {
                _UbicacionPersonas = new UbicacionPersonaRepository (_context); // Remember putting the base in the repository of this entity
            }
            return _UbicacionPersonas;
        }
    }
    public IUserRepository Users
    {
        get
        {
            if (_Users == null)
            {
                _Users = new UserRepository (_context); // Remember putting the base in the repository of this entity
            }
            return _Users;
        }
    }
    public IRolRepository Rols
    {
        get
        {
            if (_Rols == null)
            {
                _Rols = new RolRepository (_context); // Remember putting the base in the repository of this entity
            }
            return _Rols;
        }
    }
    public IRefreshTokenRepository RefreshTokens
    {
        get
        {
            if (_RefreshTokens == null)
            {
                _RefreshTokens = new RefreshTokenRepository (_context); // Remember putting the base in the repository of this entity
            }
            return _RefreshTokens;
        }
    }

    public Task<int> SaveAsync()
    {
        return _context.SaveChangesAsync();
    }

    public void Dispose()
    {
        _context.Dispose();
    }
}

```

## Domain

#### Entities

###### Entity

```csharp
namespace Domain.Entities;

public class Ciudad : BaseEntity
{
    public string NombreCiudad { get; set; }
    public int IdDepartamentoFk { get; set; }
    public Departamento Departamentos { get; set; }
    public ICollection<UbicacionPersona> UbicacionPersonas { get; set; }
}

```

###### BaseEntity

```csharp
namespace Core.Entities;

public class BaseEntity
{
    public int/string Id { get; set; }
}
```

#### 

#### Interface

###### IEntity

```csharp
using Domain.Entities;

namespace Domain.Interfaces;

public interface IMovimientoInventarioRepository : IGenericRepositoryVC<MovimientoInventario>
{

}
```

###### IUser

```csharp
using Domain.Entities;

namespace Domain.Interfaces;

public interface IUserRepository : IGenericRepository<User>
{
    Task<User> GetByUsernameAsync(string username);
    Task<User> GetByRefreshTokenAsync(string refreshToken);
}
```

###### IGenericRepository

```csharp
using System.Linq.Expressions;
using Domain.Entities;

namespace Domain.Interfaces;

public interface IGenericRepository<T> where T : BaseEntity
{
    Task<T> GetByIdAsync(int Id);
    Task<IEnumerable<T>> GetAllAsync();
    IEnumerable<T> Find(Expression<Func<T, bool>> expression);
    Task<(int totalRegistros, IEnumerable<T> registros)> GetAllAsync(int pageIndex, int pageSize, string search);
    void Add(T entity);
    void AddRange(IEnumerable<T> entities);
    void Remove(T entity);
    void RemoveRange(IEnumerable<T> entities);
    void Update(T entity);
}
```

###### IUnitOfWork

```csharp
namespace Domain.Interfaces;

public interface IUnitOfWork
{
    public IMovimientoInventario MovimientoInventarios { get; }
    ...

    Task<int> SaveAsync();
}
```

###### 

## Infrastructure

#### Data

##### Configuration

###### CiudadConfiguration

```csharp
using Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Persistance.Data.Configuration;

public class CiudadConfiguration : IEntityTypeConfiguration<Ciudad>
{
    public void Configure(EntityTypeBuilder<Ciudad> builder)
    {
        //Here you can configure the properties using the object 'Builder'.
        builder.ToTable("ciudad");

        builder.HasKey(c => c.Id);
        builder.Property(c => c.Id);

        builder.Property(c => c.NombreCiudad).IsRequired().HasMaxLength(50);

        builder.Property(x => x.IdDepartamentoFk).HasColumnType("int");
        builder.HasOne(c => c.Departamentos).WithMany(c => c.Ciudades).HasForeignKey(c => c.IdDepartamentoFk);
    }
}
```

###### DbContext

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace Persistance.Data;

public class FarmaciaFourLayersContext : DbContext
{
    public FarmaciaFourLayersContext(DbContextOptions options) : base(options)
    {
    }
    // DbSets
    public DbSet<Ciudad> Ciudades { get; set; }
    public DbSet<ContactoPersona> ContactoPersonas { get; set; }
    ...

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.ApplyConfigurationsFromAssembly(Assembly.GetExecutingAssembly());
    }
}


```