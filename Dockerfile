# Build stage
FROM mcr.microsoft.com/dotnet/sdk:10.0-preview AS build
WORKDIR /src

COPY CnCNetServer.csproj .
RUN dotnet restore CnCNetServer.csproj

COPY . .
RUN dotnet publish CnCNetServer.csproj -c Release -r linux-x64 --no-self-contained -o /app/publish

# Runtime stage
FROM mcr.microsoft.com/dotnet/runtime:10.0-preview AS runtime
WORKDIR /app

# Install curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/publish .

# Logs directory
RUN mkdir -p /app/logs

EXPOSE 50001/udp
EXPOSE 50000/udp
EXPOSE 50000/tcp
EXPOSE 8054/udp
EXPOSE 3478/udp
EXPOSE 1337/tcp

ENTRYPOINT ["./cncnet-server"]
