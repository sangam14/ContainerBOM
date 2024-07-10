# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create and set a working directory
WORKDIR /app

# Install Python dependencies using pip
RUN pip install --upgrade pip
RUN pip install \
    flask \
    requests

# Example of running a command
CMD ["python", "-m", "http.server", "8000"]

# Expose port 8000 to the outside world
EXPOSE 8000
