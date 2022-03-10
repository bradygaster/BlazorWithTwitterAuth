using Microsoft.AspNetCore.Identity;

namespace BlazorWithAuth.Server.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string? ProfilePictureUrl { get; set; }
    }
}