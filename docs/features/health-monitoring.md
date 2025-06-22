# Health Monitoring System

The GamePlan application includes a comprehensive health monitoring system that provides detailed insights into all system components, enabling proactive monitoring and quick issue identification.

## Overview

The health monitoring system provides real-time visibility into the operational status of all application components, from database connectivity to external API dependencies. It offers multiple endpoints for different monitoring needs and integrates seamlessly with existing infrastructure.

## Features

### 1. Comprehensive Health Service (`services/healthService.js`)

A centralized health monitoring service that aggregates health information from:
- **System Resources**: Memory usage, CPU load, process uptime
- **Database Connectivity**: Connection status, response times, pool metrics
- **Cache Services**: Hit rates, memory usage, service availability
- **External Dependencies**: Steam API, RAWG API connectivity
- **Configuration**: Environment variable validation

### 2. Enhanced Main Health Endpoint

**Endpoint**: `GET /api/health`

**Query Parameters**:
- `detailed=true`: Include detailed system information (Node.js version, platform, etc.)
- `quick=true`: Return cached status for faster response
- `dependencies=false`: Skip external dependency checks

**Response Example**:
```json
{
  "status": "healthy|degraded|unhealthy",
  "timestamp": "2025-06-18T22:45:06.095Z",
  "uptime": 86.744233,
  "environment": "development",
  "responseTime": "2ms",
  "version": "1.0.0",
  "system": {
    "status": "healthy",
    "memory": {
      "process": { "rss": "98.6 MB", "heapUsed": "45.7 MB" },
      "system": { "total": "31.9 GB", "usagePercent": "47.9%" }
    },
    "cpu": { "cores": 12, "loadPercent": "0.0%" }
  },
  "database": {
    "status": "healthy",
    "responseTime": "2ms",
    "connection": { "state": "connected", "poolSize": 0 },
    "metrics": { "totalConnections": 1, "totalQueries": 94 }
  },
  "cache": {
    "status": "healthy",
    "services": { "mainCache": { "hitRate": "0.0%" } }
  },
  "dependencies": {
    "status": "degraded",
    "services": {
      "steamAPI": { "status": "disabled" },
      "rawgAPI": { "status": "unhealthy" }
    }
  },
  "warnings": [],
  "errors": []
}
```

### 3. Component-Specific Health Endpoints

#### Database Health
**Endpoint**: `GET /api/health/database`
- Database connectivity status
- Response time metrics
- Connection pool information
- Query statistics

#### System Health
**Endpoint**: `GET /api/health/system`
- Memory usage (process and system)
- CPU load averages
- System and process uptime

#### Cache Health
**Endpoint**: `GET /api/health/cache`
- Individual cache service status
- Hit rates and performance metrics
- Memory usage per cache service

#### Dependencies Health
**Endpoint**: `GET /api/health/dependencies`
- External API connectivity status
- Response time monitoring
- Service availability checks

#### Health History
**Endpoint**: `GET /api/health/history?limit=10`
- Recent health check history
- Trend analysis data
- Performance over time

## Health Status Levels

### Healthy ✅
- All systems operational
- No critical issues
- Performance within normal ranges

### Degraded ⚠️
- System functional but with warnings
- Non-critical issues present
- Performance may be impacted

### Unhealthy ❌
- Critical system failures
- Service unavailable
- Immediate attention required

## Monitoring Features

### 1. Intelligent Status Determination
- Automatic health assessment based on component status
- Configurable thresholds for memory and performance
- Hierarchical status aggregation

### 2. Performance Tracking
- Response time monitoring for all components
- Database query performance metrics
- Cache hit rate analysis

### 3. Dependency Validation
- External API connectivity testing
- Timeout handling and error recovery
- Service availability caching

### 4. Memory Management
- Process memory usage tracking
- System memory utilization
- Memory leak detection capabilities

### 5. Historical Data
- Health check history storage
- Trend analysis support
- Performance baseline establishment

## Configuration Integration

The health system integrates with existing configuration validation:
- Environment variable validation
- Production safety checks
- Development mode detection
- Security configuration verification

## Error Handling

### Graceful Degradation
- Individual component failures don't crash the health system
- Fallback responses for unavailable services
- Comprehensive error logging

### Timeout Management
- 10-second timeout for external dependency checks
- 30-second caching for dependency status
- Non-blocking health checks

## Usage Examples

### Basic Health Check
```bash
curl http://localhost:3000/api/health
```

### Detailed Health Information
```bash
curl "http://localhost:3000/api/health?detailed=true"
```

### Quick Status (Cached)
```bash
curl "http://localhost:3000/api/health?quick=true"
```

### Database-Specific Health
```bash
curl http://localhost:3000/api/health/database
```

### Health History
```bash
curl "http://localhost:3000/api/health/history?limit=5"
```

## Integration with Existing Systems

### Swagger Documentation
- All endpoints fully documented in Swagger
- Interactive API testing available
- Comprehensive schema definitions

### Logging Integration
- Health check events logged via Winston
- Error tracking with request IDs
- Performance metrics logging

### Rate Limiting
- Health endpoints respect existing rate limits
- Optimized for monitoring tools
- Quick check option for high-frequency polling

## Monitoring Tool Integration

The health endpoints are designed to work with:

### Docker Health Checks
Use `/api/health?quick=true` for container health checks:
```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/api/health?quick=true || exit 1
```

### Kubernetes Probes
Configure liveness and readiness probes:
```yaml
livenessProbe:
  httpGet:
    path: /api/health
    port: 3000
  initialDelaySeconds: 30
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /api/health?quick=true
    port: 3000
  initialDelaySeconds: 5
  periodSeconds: 5
```

### Load Balancers
Monitor `/api/health` for service availability and automatic failover.

### APM Tools
Detailed metrics available via component endpoints for application performance monitoring.

### Alerting Systems
Use status levels and error arrays for alert triggers:
```bash
# Example alert check
STATUS=$(curl -s http://localhost:3000/api/health | jq -r '.status')
if [ "$STATUS" != "healthy" ]; then
  echo "ALERT: Service is $STATUS"
fi
```

## Performance Considerations

### Caching Strategy
- **30-second cache** for dependency checks
- **Quick status option** for high-frequency monitoring
- **Minimal overhead** for basic health checks

### Resource Usage
- **Non-blocking health checks** - Don't impact application performance
- **Parallel component evaluation** - Faster response times
- **Optimized memory usage tracking** - Minimal performance impact

### Scalability
- **Stateless health service design** - Works in clustered environments
- **Configurable history retention** - Manage storage requirements
- **Efficient data structures** - Optimized for performance

## API Reference

### Main Health Endpoint

#### GET /api/health
**Query Parameters:**
- `detailed` (boolean): Include detailed system information
- `quick` (boolean): Return cached status for faster response
- `dependencies` (boolean): Include/exclude external dependency checks

**Response:**
```json
{
  "status": "healthy|degraded|unhealthy",
  "timestamp": "ISO 8601 timestamp",
  "uptime": "seconds",
  "environment": "development|production",
  "responseTime": "response time in ms",
  "version": "application version",
  "system": { /* system metrics */ },
  "database": { /* database status */ },
  "cache": { /* cache status */ },
  "dependencies": { /* external dependencies */ },
  "warnings": [ /* warning messages */ ],
  "errors": [ /* error messages */ ]
}
```

### Component Endpoints

#### GET /api/health/database
Returns detailed database health information.

#### GET /api/health/system
Returns system resource utilization.

#### GET /api/health/cache
Returns cache service status and metrics.

#### GET /api/health/dependencies
Returns external dependency status.

#### GET /api/health/history
Returns historical health data.
**Query Parameters:**
- `limit` (number): Number of historical records to return

## Troubleshooting

### Common Issues

#### Health Check Timeouts
- Check external API connectivity
- Verify network configuration
- Review timeout settings

#### Database Health Issues
- Verify MongoDB connection
- Check database credentials
- Review connection pool settings

#### Cache Health Problems
- Check cache service configuration
- Verify memory availability
- Review cache hit rates

### Debugging

#### Enable Debug Logging
```bash
LOG_LEVEL=debug npm start
```

#### Check Individual Components
```bash
# Test database connectivity
curl http://localhost:3000/api/health/database

# Check system resources
curl http://localhost:3000/api/health/system

# Verify cache status
curl http://localhost:3000/api/health/cache
```

#### Monitor Health History
```bash
# Get recent health trends
curl "http://localhost:3000/api/health/history?limit=20"
```

## Future Enhancements

### Planned Features
1. **Metrics Export**: Prometheus/Grafana integration
2. **Alert Thresholds**: Configurable warning/error levels
3. **Custom Health Checks**: Plugin system for application-specific checks
4. **Health Dashboard**: Web UI for health visualization
5. **Notification System**: Email/Slack alerts for critical issues

### Integration Opportunities
1. **External Monitoring Services**: DataDog, New Relic integration
2. **Log Aggregation**: ELK stack integration
3. **Metrics Collection**: StatsD/Prometheus metrics
4. **Automated Remediation**: Self-healing capabilities

## Related Documentation

- [Error Handling](../architecture/error-handling.md) - Error handling and logging
- [Caching System](../architecture/caching-system.md) - Cache monitoring details
- [Database Management](../operations/database-management.md) - Database health specifics
- [Docker Deployment](../deployment/docker-deployment.md) - Container health checks

## Support

For issues or questions regarding the health monitoring system:

1. Check the troubleshooting section above
2. Review application logs for health-related errors
3. Test individual component endpoints
4. Verify external dependency connectivity
5. Check system resource availability

This comprehensive health monitoring system provides deep visibility into the GamePlan application's operational status, enabling proactive monitoring, quick issue identification, and reliable service management.
