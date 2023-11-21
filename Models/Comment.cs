using System;
using System.ComponentModel.DataAnnotations;

namespace UserDashboard.Models
{
    public class Comment
    {
        [Key]
        public int CommentId { get; set; }

        [Required]
        [MinLength(2, ErrorMessage = "Comment must be at least 2 characters long.")]
        public string CommentText { get; set; }

        [Required]
        public int UserId { get; set; }
        public User User { get; set; }

        [Required]
        public int MessageId { get; set; }
        public Message Message { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.Now;
        public DateTime UpdatedAt { get; set; } = DateTime.Now;

    }
}