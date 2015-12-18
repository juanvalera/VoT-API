using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VoTAPI.Models
{
    public class FitbitCodeRequest
    {
        [Required]
        public string Code { get; set; }
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
