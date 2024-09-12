using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Threading.RateLimiting;
using System.Threading.Tasks;
using API.Constants;
using API.Data;
using API.Data.ManualMigrations;
using API.Entities;
using API.Entities.Enums;
using API.Extensions;
using API.Logging;
using API.Middleware;
using API.Middleware.RateLimit;
using API.Services;
using API.Services.HostedServices;
using API.Services.Tasks;
using API.SignalR;
using Hangfire;
using HtmlAgilityPack;
using Kavita.Common;
using Kavita.Common.EnvironmentInfo;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;
using Microsoft.OpenApi.Models;
using Serilog;
using TaskScheduler = API.Services.TaskScheduler;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace API;

public class Startup
{
    private readonly IConfiguration _config;
    private readonly IWebHostEnvironment _env;

    public Startup(IConfiguration config, IWebHostEnvironment env)
    {
        _config = config;
        _env = env;
    }

    // This method gets called by the runtime. Use this method to add services to the container.
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddApplicationServices(_config, _env);

        services.AddControllers(options =>
        {
            options.CacheProfiles.Add(ResponseCacheProfiles.Instant,
                new CacheProfile()
                {
                    Duration = 30,
                    Location = ResponseCacheLocation.None,
                });
            options.CacheProfiles.Add(ResponseCacheProfiles.FiveMinute,
                new CacheProfile()
                {
                    Duration = 60 * 5,
                    Location = ResponseCacheLocation.None,
                });
            options.CacheProfiles.Add(ResponseCacheProfiles.TenMinute,
                new CacheProfile()
                {
                    Duration = 60 * 10,
                    Location = ResponseCacheLocation.None,
                    NoStore = false
                });
            options.CacheProfiles.Add(ResponseCacheProfiles.Hour,
                new CacheProfile()
                {
                    Duration = 60 * 60,
                    Location = ResponseCacheLocation.None,
                    NoStore = false
                });
            options.CacheProfiles.Add(ResponseCacheProfiles.Statistics,
                new CacheProfile()
                {
                    Duration = 60 * 60 * 6,
                    Location = ResponseCacheLocation.None,
                });
            options.CacheProfiles.Add(ResponseCacheProfiles.Images,
                new CacheProfile()
                {
                    Duration = 60,
                    Location = ResponseCacheLocation.None,
                    NoStore = false
                });
            options.CacheProfiles.Add(ResponseCacheProfiles.Month,
                new CacheProfile()
                {
                    Duration = TimeSpan.FromDays(30).Seconds,
                    Location = ResponseCacheLocation.Client,
                    NoStore = false
                });
            options.CacheProfiles.Add(ResponseCacheProfiles.LicenseCache,
                new CacheProfile()
                {
                    Duration = TimeSpan.FromHours(4).Seconds,
                    Location = ResponseCacheLocation.Client,
                    NoStore = false
                });
            options.CacheProfiles.Add(ResponseCacheProfiles.KavitaPlus,
                new CacheProfile()
                {
                    Duration = TimeSpan.FromDays(30).Seconds,
                    Location = ResponseCacheLocation.Any,
                    NoStore = false
                });
        });
        services.Configure<ForwardedHeadersOptions>(options =>
        {
            options.ForwardedHeaders = ForwardedHeaders.All;
            foreach(var proxy in _config.GetSection("KnownProxies").AsEnumerable().Where(c => c.Value != null)) {
                options.KnownProxies.Add(IPAddress.Parse(proxy.Value!));
            }
        });
        services.AddCors();
        services.AddIdentityServices(_config);

        // Add OpenID Connect Authentication
        services.AddAuthentication(options =>
        {
            options.DefaultScheme = "Bearer";
            options.DefaultChallengeScheme = "oidc";
        })
        .AddJwtBearer("Bearer", options =>
        {
            options.Authority = _config["Jwt:Issuer"];
            options.Audience = _config["Jwt:Audience"];
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"])),
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };
        })
        .AddOpenIdConnect("oidc", options =>
        {
            options.Authority = _config["OIDC:Authority"];
            options.ClientId = _config["OIDC:ClientId"];
            options.ClientSecret = _config["OIDC:ClientSecret"];
            options.ResponseType = "code";
            options.SaveTokens = true;
            options.GetClaimsFromUserInfoEndpoint = true;
            options.Scope.Add("openid");
            options.Scope.Add("profile");
            options.Scope.Add("email");
        });

        services.AddSwaggerGen(c =>
        {
            c.SwaggerDoc("v1", new OpenApiInfo
            {
                Version = "3.1.0",
                Title = "Kavita",
                Description = $"Kavita provides a set of APIs that are authenticated by JWT. JWT token can be copied from local storage. Assume all fields of a payload are required. Built against v{BuildInfo.Version.ToString()}",
                License = new OpenApiLicense
                {
                    Name = "GPL-3.0",
                    Url = new Uri("https://github.com/Kareadita/Kavita/blob/develop/LICENSE")
                },
            });

            var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
            var filePath = Path.Combine(AppContext.BaseDirectory, xmlFile);
            c.IncludeXmlComments(filePath, true);
            c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme {
                In = ParameterLocation.Header,
                Description = "Please insert JWT with Bearer into field",
                Name = "Authorization",
                Type = SecuritySchemeType.ApiKey
            });

            c.AddSecurityRequirement(new OpenApiSecurityRequirement {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        }
                    },
                    Array.Empty<string>()
                }
            });

            c.AddServer(new OpenApiServer
            {
                Url = "{protocol}://{hostpath}",
                Variables = new Dictionary<string, OpenApiServerVariable>
                {
                    { "protocol", new OpenApiServerVariable { Default = "http", Enum = ["http", "https"]} },
                    { "hostpath", new OpenApiServerVariable { Default = "localhost:5000" } }
                }
            });
        });
        services.AddResponseCompression(options =>
        {
            options.Providers.Add<BrotliCompressionProvider>();
            options.Providers.Add<GzipCompressionProvider>();
            options.MimeTypes =
                ResponseCompressionDefaults.MimeTypes.Concat(
                    new[] { "image/jpeg", "image/jpg", "image/png", "image/avif", "image/gif", "image/webp", "image/tiff" });
            options.EnableForHttps = true;
        });
        services.Configure<BrotliCompressionProviderOptions>(options =>
        {
            options.Level = CompressionLevel.Fastest;
        });

        services.AddResponseCaching();

        services.AddRateLimiter(options =>
        {
            options.AddPolicy("Authentication", httpContext =>
                new AuthenticationRateLimiterPolicy().GetPartition(httpContext));
        });

        services.AddHangfire(configuration => configuration
            .UseSimpleAssemblyNameTypeSerializer()
            .UseRecommendedSerializerSettings()
            .UseInMemoryStorage());

        // Add the processing server as IHostedService
        services.AddHangfireServer(options =>
        {
            options.Queues = new[] {TaskScheduler.ScanQueue, TaskScheduler.DefaultQueue};
        });
        // Add IHostedService for startup tasks
        // Any services that should be bootstrapped go here
        services.AddHostedService<StartupTasksHostedService>();
    }

    // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
    public void Configure(IApplicationBuilder app, IBackgroundJobClient backgroundJobs, IWebHostEnvironment env,
        IHostApplicationLifetime applicationLifetime, IServiceProvider serviceProvider, ICacheService cacheService,
        IDirectoryService directoryService, IUnitOfWork unitOfWork, IBackupService backupService, IImageService imageService)
    {
        // ... (rest of the Configure method remains unchanged)
    }

    // ... (rest of the class remains unchanged)
}
