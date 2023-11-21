using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;


namespace UserDashboard.Models
{
    public class User
    {
        [Key] public int UserId { get; set; }

        [Required(ErrorMessage = "*Required")]
        [MinLength(2, ErrorMessage = "*Needs to be at least 2 characters")]
        [Display(Name = "First Name", Prompt = "First Name")]
        public string FirstName { get; set; }

        [Required(ErrorMessage = "*Required")]
        [MinLength(2, ErrorMessage = "*Needs to be at least 2 characters")]
        [Display(Name = "Last Name", Prompt = "Last Name")]
        public string LastName { get; set; }

        [Required(ErrorMessage = "*Required")]
        [EmailAddress]
        [Display(Name = "Email", Prompt = "Email")]
        public string Email { get; set; }

        public string Description { get; set; }

        public string UserLevel { get; set; }

        [Required(ErrorMessage = "*Required")]
        [MinLength(8)]
        [DataType(DataType.Password)]
        [Display(Name = "Password", Prompt = "Password")]

        public string Password { get; set; }

        [NotMapped]
        [Required(ErrorMessage = "*Required")]
        [Compare("Password")]
        [DataType(DataType.Password)]
        [Display(Name = "Confirm Password", Prompt = "Confirm Password")]
        public string Confirm { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.Now;
        public DateTime UpdatedAt { get; set; } = DateTime.Now;

        // Relationships
        public List<Message> AuthorUserMessages { get; set; }
        // public List<Comment> AuthorComments { get; set; }
        // public List<Message> TargetMessages { get; set; }

        public List<string> UserLevels()
        {
            List<string> userLevels = new List<string>();
            userLevels.Add("Admin");
            userLevels.Add("Normal");

            return userLevels;
        }
    }
}