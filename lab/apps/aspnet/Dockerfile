FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src
COPY LabApp.csproj Program.cs ./
RUN dotnet publish -c Release -o /out
FROM mcr.microsoft.com/dotnet/aspnet:9.0
COPY --from=build /out /app
WORKDIR /app
ENV PORT=8000
EXPOSE 8000
ENTRYPOINT ["dotnet", "LabApp.dll"]
