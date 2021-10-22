from timescale/timescaledb:latest-pg12
env POSTGRES_USER     postgres
env POSTGRES_PASSWORD password
env POSTGRES_USER postgres


WORKDIR /app

add 01_setup.sh /app
add setup_tables.sql /app
run chmod +x 01_setup.sh
copy 01_setup.sh /docker-entrypoint-initdb.d
expose 5432

