FROM ruby:3.3-slim
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libyaml-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Gemfile .
RUN bundle install
COPY config.ru .
EXPOSE 8000
CMD ["bundle", "exec", "puma", "-b", "tcp://0.0.0.0:8000", "-t", "4:16", "config.ru"]
