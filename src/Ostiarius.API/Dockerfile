FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY Directory.Build.props Ostiarius.slnx ./
COPY src/ ./src/
RUN dotnet publish src/Ostiarius.API/Ostiarius.API.csproj -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app .
EXPOSE 80 443
VOLUME ["/data/acme"]
ENV ASPNETCORE_URLS=http://+:80;https://+:443
ENTRYPOINT ["dotnet", "Ostiarius.API.dll"]
