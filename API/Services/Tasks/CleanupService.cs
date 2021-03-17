﻿using System.IO;
using API.Interfaces.Services;
using Hangfire;
using Microsoft.Extensions.Logging;

namespace API.Services.Tasks
{
    /// <summary>
    /// Cleans up after operations on reoccurring basis
    /// </summary>
    public class CleanupService : ICleanupService
    {
        private readonly ICacheService _cacheService;
        private readonly IDirectoryService _directoryService;
        private readonly ILogger<CleanupService> _logger;

        public CleanupService(ICacheService cacheService, IDirectoryService directoryService, ILogger<CleanupService> logger)
        {
            _cacheService = cacheService;
            _directoryService = directoryService;
            _logger = logger;
        }

        [AutomaticRetry(Attempts = 3, LogEvents = false, OnAttemptsExceeded = AttemptsExceededAction.Fail)]
        public void Cleanup()
        {
            _logger.LogInformation("Cleaning temp directory");
            var tempDirectory = Path.Join(Directory.GetCurrentDirectory(), "temp");
            _directoryService.ClearDirectory(tempDirectory);
            _logger.LogInformation("Cleaning cache directory");
            _cacheService.Cleanup();
            
        }
    }
}