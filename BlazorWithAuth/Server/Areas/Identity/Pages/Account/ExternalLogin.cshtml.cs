// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using BlazorWithAuth.Server.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;
using Tweetinvi;

namespace BlazorWithAuth.Server.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class ExternalLoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IUserStore<ApplicationUser> _userStore;
        private readonly IUserEmailStore<ApplicationUser> _emailStore;
        private readonly ILogger<ExternalLoginModel> _logger;
        private readonly IConfiguration _configuration;

        public ExternalLoginModel(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            IUserStore<ApplicationUser> userStore,
            ILogger<ExternalLoginModel> logger,
            IConfiguration configuration)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _userStore = userStore;
            _emailStore = GetEmailStore();
            _logger = logger;
            _configuration = configuration;
        }

        [TempData]
        public string ErrorMessage { get; set; }
        
        public IActionResult OnGet() => RedirectToPage("./Login");

        public IActionResult OnPost(string provider, string returnUrl = null)
        {
            // Request a redirect to the external login provider.
            var redirectUrl = Url.Page("./ExternalLogin", pageHandler: "Callback", values: new { returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return new ChallengeResult(provider, properties);
        }

        public async Task<IActionResult> OnGetCallbackAsync(string returnUrl = null, string remoteError = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            if (remoteError != null)
            {
                ErrorMessage = $"Error from external provider: {remoteError}";
                return RedirectToPage("./Login", new { ReturnUrl = returnUrl });
            }
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                ErrorMessage = "Error loading external login information.";
                return RedirectToPage("./Login", new { ReturnUrl = returnUrl });
            }

            // Sign in the user with this external login provider if the user already has a login.
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
            if (result.Succeeded)
            {
                _logger.LogInformation("{Name} logged in with {LoginProvider} provider.", info.Principal.Identity.Name, info.LoginProvider);
                return LocalRedirect(returnUrl);
            }
            if (result.IsLockedOut)
            {
                return RedirectToPage("./Lockout");
            }
            else
            {
                // Get the information about the user from the external login provider
                info = await _signInManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    ErrorMessage = "Error loading external login information during confirmation.";
                    return RedirectToPage("./Login", new { ReturnUrl = returnUrl });
                }

                if (ModelState.IsValid)
                {
                    var user = CreateUser();

                    // save the tokens
                    var token = info.AuthenticationTokens.First(_ => _.Name == "access_token").Value;
                    var tokenSecret = info.AuthenticationTokens.First(_ => _.Name == "access_token_secret").Value;
                    await _userManager.AddClaimsAsync(user, new Claim[]
                    {
                            new Claim("TwitterAccessToken", token),
                            new Claim("TwitterAccessTokenSecret", tokenSecret)
                    });

                    // get the profile image
                    var userClient = new TwitterClient(
                        _configuration.GetValue<string>("TwitterConsumerKey"),
                        _configuration.GetValue<string>("TwitterConsumerKeySecret"),
                        token,
                        tokenSecret
                        );
                    var twitterUser = await userClient.Users.GetAuthenticatedUserAsync();
                    user.ProfilePictureUrl = twitterUser.ProfileImageUrl;
                    user.EmailConfirmed = true;
                    user.Email = twitterUser.Email;
                    user.NormalizedEmail = twitterUser.Email;
                    await _userManager.UpdateAsync(user);
                    await _userStore.SetUserNameAsync(user, twitterUser.Email, CancellationToken.None);
                    await _emailStore.SetEmailAsync(user, twitterUser.Email, CancellationToken.None);

                    var createResult = await _userManager.CreateAsync(user);
                    if (createResult.Succeeded)
                    {
                        createResult = await _userManager.AddLoginAsync(user, info);
                        if (createResult.Succeeded)
                        {
                            _logger.LogInformation("User created an account using {Name} provider.", info.LoginProvider);

                            await _signInManager.SignInAsync(user, isPersistent: false, info.LoginProvider);
                            return LocalRedirect(returnUrl);
                        }
                    }
                    foreach (var error in createResult.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                }

                return LocalRedirect(returnUrl);
            }
        }

        private ApplicationUser CreateUser()
        {
            try
            {
                return Activator.CreateInstance<ApplicationUser>();
            }
            catch
            {
                throw new InvalidOperationException($"Can't create an instance of '{nameof(ApplicationUser)}'. " +
                    $"Ensure that '{nameof(ApplicationUser)}' is not an abstract class and has a parameterless constructor, or alternatively " +
                    $"override the external login page in /Areas/Identity/Pages/Account/ExternalLogin.cshtml");
            }
        }

        private IUserEmailStore<ApplicationUser> GetEmailStore()
        {
            if (!_userManager.SupportsUserEmail)
            {
                throw new NotSupportedException("The default UI requires a user store with email support.");
            }
            return (IUserEmailStore<ApplicationUser>)_userStore;
        }
    }
}
