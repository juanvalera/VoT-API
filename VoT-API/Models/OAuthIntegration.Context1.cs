﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace VoTAPI.Models
{
    using System;
    using System.Data.Entity;
    using System.Data.Entity.Infrastructure;
    
    public partial class OAuthIntegrationEntities : DbContext
    {
        public OAuthIntegrationEntities()
            : base("name=OAuthIntegrationEntities")
        {
        }
    
        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            throw new UnintentionalCodeFirstException();
        }
    
        public virtual DbSet<ThirdPartyServices> ThirdPartyServices { get; set; }
        public virtual DbSet<ThirdPartyUserIdentity> ThirdPartyUserIdentity { get; set; }
    }
}
