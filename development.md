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
dotnet tool update -g coverlet.console

# https://github.com/danielpalme/ReportGenerator
dotnet tool update -g dotnet-reportgenerator-globaltool

dotnet test -c Release -v minimal --nologo --logger trx --results-directory ./artifacts/test-results --collect:"XPlat Code Coverage"
reportgenerator -reports:artifacts/test-results/**/coverage.cobertura.xml -targetdir:artifacts -reporttypes:MarkdownSummaryGithub
```

Then you can find results in `./artifacts/SummaryGithub.md`.


### Run basic benchmarks and output reports

```shell
dotnet publish bench/Encryption.Blowfish.Benchmarks/Encryption.Blowfish.Benchmarks.csproj -c Release -p:RunAnalyzers=False -o ./artifacts/bench -v minimal --nologo
./artifacts/bench/Encryption.Blowfish.Benchmarks -r net10.0 -m -e GitHub -a ./artifacts/bench -f *
```

Then you can find results in `./artifacts/bench/results` directory.
