# Multi-stage build for GamePlan application
FROM node:24.2.0-alpine AS base

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy application code
COPY . .

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S gameplan -u 1001

# Create logs directories with proper permissions
RUN mkdir -p /app/logs/application /app/logs/errors /app/logs/debug && \
    chown -R gameplan:nodejs /app && \
    chmod -R 755 /app/logs

USER gameplan

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/api/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) }).on('error', () => process.exit(1))"

# Start the application
CMD ["npm", "start"]
