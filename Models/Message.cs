using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace UserDashboard.Models
{
    public class Message
    {
        [Key]
        public int MessageId { get; set; }
        [Required]
        [MinLength(2, ErrorMessage = "Message must be at least 2 characters")]
        public string MessageText { get; set; }

        // Author of the message
        public int AuthorUserId { get; set; }
        public User AuthorUser { get; set; }

        // Target of the message
        public int TargetUserId { get; set; }
        public User TargetUser { get; set; }

        // Date of the message
        public DateTime CreatedAt { get; set; } = DateTime.Now;
        public DateTime UpdatedAt { get; set; } = DateTime.Now;

        // List of comments
        public List<Comment> Comments { get; set; }
    }
}