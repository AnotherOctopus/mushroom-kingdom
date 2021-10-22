#!/bin/bash
psql -U "${POSTGRES_USER}" postgres -f setup_tables.sql

