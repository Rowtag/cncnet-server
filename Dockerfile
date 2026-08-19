# Build stage
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY CnCNetServer.csproj .
RUN dotnet restore CnCNetServer.csproj

COPY . .
RUN dotnet publish CnCNetServer.csproj -c Release -r linux-x64 --self-contained true -o /app/publish

# Runtime stage
FROM mcr.microsoft.com/dotnet/runtime-deps:10.0 AS runtime
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/publish .

# Geo country database (DB-IP Country Lite, CC-BY)
# Optional country database (DB-IP Country Lite). The bracket makes the pattern a
# glob, so the build still succeeds when the file is not present in the context.
COPY dbip-country-lite.mmd[b] /app/

RUN mkdir -p /app/logs

EXPOSE 50001/udp
EXPOSE 50000/udp
EXPOSE 50000/tcp
EXPOSE 8054/udp
EXPOSE 3478/udp
EXPOSE 1337/tcp

ENTRYPOINT ["./cncnet-server"]
