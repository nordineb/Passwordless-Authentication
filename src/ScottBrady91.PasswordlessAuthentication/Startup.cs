
using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace ScottBrady91.PasswordlessAuthentication
{

    public class PasswordlessLoginTokenProviderOptions : DataProtectionTokenProviderOptions
    {
        public PasswordlessLoginTokenProviderOptions()
        {
            // update the defaults
            Name = "PasswordlessLoginTokenProvider";
            TokenLifespan = TimeSpan.FromMinutes(15);
        }
    }

    public class PasswordlessLoginTokenProvider<TUser> : DataProtectorTokenProvider<TUser>
            where TUser : class
    {
        public PasswordlessLoginTokenProvider(
            IDataProtectionProvider dataProtectionProvider,
            IOptions<PasswordlessLoginTokenProviderOptions> options)
            : base(dataProtectionProvider, options)
        {
        }
    }
    public class PasswordlessLoginTotpTokenProvider<TUser> : TotpSecurityStampBasedTokenProvider<TUser>
        where TUser : class
    {
        public override Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<TUser> manager, TUser user)
        {
            return Task.FromResult(false);
        }

        public override async Task<string> GetUserModifierAsync(string purpose, UserManager<TUser> manager, TUser user)
        {
            var email = await manager.GetEmailAsync(user);
            return "PasswordlessLogin:" + purpose + ":" + email;
        }
    }

    public static class CustomIdentityBuilderExtensions
    {
        public static IdentityBuilder AddPasswordlessLoginTotpTokenProvider(this IdentityBuilder builder)
        {
            var userType = builder.UserType;
            var totpProvider = typeof(PasswordlessLoginTotpTokenProvider<>).MakeGenericType(userType);
            return builder.AddTokenProvider("PasswordlessLoginTotpProvider", totpProvider);
        }

        public static IdentityBuilder AddPasswordlessLoginTokenProvider(this IdentityBuilder builder)
        {
            var userType = builder.UserType;
            var provider= typeof(PasswordlessLoginTokenProvider<>).MakeGenericType(userType);
            return builder.AddTokenProvider("PasswordlessLoginProvider", provider);
        }


    }

    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<DataProtectionTokenProviderOptions>(
                x => x.TokenLifespan = TimeSpan.FromMinutes(15));

            services.AddMvc();

            services.AddDbContext<IdentityDbContext>(opt => opt.UseInMemoryDatabase("Passwordless"));

            services.AddIdentity<IdentityUser, IdentityRole>()
                .AddEntityFrameworkStores<IdentityDbContext>()
                .AddDefaultTokenProviders()
                //.AddPasswordlessLoginTokenProvider() // Add the token provider
                .AddPasswordlessLoginTotpTokenProvider(); // Add the custom token provider

            services.Configure<DataProtectionTokenProviderOptions>(options => options.TokenLifespan = TimeSpan.FromMinutes(15));
        }

        public void Configure(IApplicationBuilder app)
        {
            app.UseDeveloperExceptionPage();

            app.UseAuthentication();

            app.UseStaticFiles();
            app.UseMvcWithDefaultRoute();
        }
    }
}
