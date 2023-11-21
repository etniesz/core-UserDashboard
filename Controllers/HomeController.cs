using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using UserDashboard.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Http;

namespace UserDashboard.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private MyContext dbContext;

        public HomeController(ILogger<HomeController> logger, MyContext context)
        {
            _logger = logger;
            dbContext = context;
        }

        public IActionResult Index()
        {
            var userInDb = dbContext.Users.FirstOrDefault(u => u.UserId == HttpContext.Session.GetInt32("UserId"));

            ViewBag.UserLoggedIn = userInDb;
            return View();
        }

        [HttpGet("dashboard")]
        public IActionResult Dashboard()
        {
            if (HttpContext.Session.GetInt32("UserId") == null)
            {
                TempData["AuthError"] = "You must be logged in to view this page";
                return RedirectToAction("Index");
            }

            var userInDb = dbContext.Users.FirstOrDefault(u => u.UserId == HttpContext.Session.GetInt32("UserId"));

            Console.WriteLine("User Logged In: ", HttpContext.Session.GetInt32("UserId"));

            ViewBag.UserLoggedIn = userInDb;

            var allUsers = dbContext.Users
                .ToList();

            return View(allUsers);
        }

        [HttpPost("PostMessage")]
        public IActionResult PostMessage(Message message)
        {
            dbContext.Messages.Add(message);
            dbContext.SaveChanges();

            return RedirectToAction("UserProfile", "Auth", new { id = message.TargetUserId });

        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}