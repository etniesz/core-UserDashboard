using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace UserDashboard.Models
{
    public class LoginUser
    {
        [Required(ErrorMessage = "*Is required")]
        [EmailAddress]
        [Display(Name = "Email", Prompt = "Email")]
        public string Email { get; set; }

        [Required(ErrorMessage = "*Is required")]
        [DataType(DataType.Password)]
        [Display(Name = "Password", Prompt = "Password")]
        public string Password { get; set; }
    }

    public class EditUserInformation
    {
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
        public int UserId { get; set; }
    }
    public class EditUserDescription
    {
        [Required(ErrorMessage = "*Required")]
        [MinLength(2, ErrorMessage = "*Needs to be at least 2 characters")]
        [Display(Name = "Description", Prompt = "Description")]
        public string Description { get; set; }
        public int UserId { get; set; }
    }

    public class EditUserAsAdmin
    {
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
        public int UserId { get; set; }
    }

    public class EditUserPassword
    {
        [Required(ErrorMessage = "*Required")]
        [MinLength(8, ErrorMessage = "*Needs to be at least 8 characters")]
        [DataType(DataType.Password)]
        [Display(Name = "Password", Prompt = "Password")]
        public string Password { get; set; }

        [Required(ErrorMessage = "*Required")]
        [MinLength(8, ErrorMessage = "*Needs to be at least 8 characters")]
        [DataType(DataType.Password)]
        [Display(Name = "Confirm Password", Prompt = "Confirm Password")]
        public string Confirm { get; set; }
        public int UserId { get; set; }
    }
}