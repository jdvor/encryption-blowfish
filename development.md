# Development

### Run tests
```shell
dotnet test -v minimal --nologo
```

### Build strict
(code analysis ON, warnings as errors)
```shell
dotnet clean -c Release -v quiet --nologo
dotnet build -c Release -v minimal -p:TreatWarningsAsErrors=True --nologo -clp:NoSummary
```

### Build permissive
(code analysis OFF)
```shell
dotnet clean -c Release -v quiet --nologo
dotnet build -c Release -v minimal -p:RunAnalyzers=False --nologo -clp:NoSummary
```

### Tag version
```shell
git tag -a "2.0.0" -m "version 2.0.0" [ commit ]
git push --tags
```

### Create NuGet package (CI variant)
```shell
./pack.sh -c
```

### Create NuGet package (local development)
```shell
./pack.sh [ -v {version_prefix} ] [ -s {version_suffix} ] [ -p {nuget_package_cache} ]
```

### Publish NuGet (local development)
```shell
./pack.sh [ -v {version_prefix} ] [ -s {version_suffix} ] [ -p {nuget_package_cache} ]
./publish.sh [ {nuget_api_key} ]
```

### Test coverage & report
```shell
# https://github.com/coverlet-coverage/coverlet
dotnet tool install -g coverlet.console

# https://github.com/danielpalme/ReportGenerator
dotnet tool install -g dotnet-reportgenerator-globaltool

dotnet test --collect:"XPlat Code Coverage" --results-directory publish/coverage
reportgenerator -reports:publish/coverage/**/coverage.cobertura.xml -targetdir:publish/report -reporttypes:HtmlInline
```

Then you can find results in `./publish/report` directory.

### Run basic benchmarks and output reports to publish directory
```shell
dotnet publish bench/Encryption.Blowfish.Benchmarks/Encryption.Blowfish.Benchmarks.csproj -c Release -p:RunAnalyzers=False -o ./publish/bench -v minimal --nologo
./publish/bench/Encryption.Blowfish.Benchmarks -a publish -e GitHub -f Encryption.Blowfish.Benchmarks.*
```

Then you can find results in `./publish/results` directory.
