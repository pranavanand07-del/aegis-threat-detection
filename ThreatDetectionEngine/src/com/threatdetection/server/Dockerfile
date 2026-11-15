
FROM eclipse-temurin:21-jdk

WORKDIR /app

COPY . .

RUN mkdir -p out && javac -encoding UTF-8 \
    --add-modules jdk.httpserver \
    -d out \
    -sourcepath src \
    src/com/threatdetection/Main.java

EXPOSE 10000

CMD ["java", "--add-modules", "jdk.httpserver", "-Dbind=0.0.0.0", "-cp", "out", "com.threatdetection.Main"]
