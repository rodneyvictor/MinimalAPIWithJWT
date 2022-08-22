#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["MinimalAPIWithJWT/MinimalAPIWithJWT.csproj", "MinimalAPIWithJWT/"]
RUN dotnet restore "MinimalAPIWithJWT/MinimalAPIWithJWT.csproj"
COPY . .
WORKDIR "/src/MinimalAPIWithJWT"
RUN dotnet build "MinimalAPIWithJWT.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "MinimalAPIWithJWT.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "MinimalAPIWithJWT.dll"]