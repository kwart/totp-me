# Kostra Java ME aplikace pro Jendu

## Co nainstalovat předem:

* JDK 8
* Apache Maven
* Git

## Postup

Stažení zdrojáků

```bash
git clone -b tmp-jenda https://github.com/kwart/totp-me.git
```

kompilace a vytvoření JARu

```bash
mvn clean package
```

## Spuštění v microemulatoru

```bash
mvn exec:java
```
