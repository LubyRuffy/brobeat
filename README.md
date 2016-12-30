Brobeat (WIP)
=============

[![Build Status](https://travis-ci.org/blacktop/brobeat.svg?branch=master)](https://travis-ci.org/blacktop/brobeat) [![License](https://img.shields.io/badge/licence-Apache%202.0-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0) [![codecov](https://codecov.io/gh/blacktop/brobeat/branch/master/graph/badge.svg)](https://codecov.io/gh/blacktop/brobeat)

### DISCUSSION HERE - https://discuss.elastic.co/t/question-about-creating-brobeat

Welcome to Brobeat.

Start Elastic Stack

```bash
$ docker run -d --name elstack -p 80:80 -p 9200:9200 blacktop/elastic-stack
```

```bash
$ git clone https://github.com/blacktop/brobeat.git
$ cd brobeat
$ make
$ ./brobeat -e -c brobeat.yml
```

### Issues

Find a bug? Want more features? Find something missing in the documentation? Let me know! Please don't hesitate to [file an issue](https://github.com/blacktop/brobeat/issues/new)

### CHANGELOG

See [`CHANGELOG.md`](https://github.com/blacktop/brobeat/blob/master/CHANGELOG.md)

### Contributing

Please start by reading our [CONTRIBUTING](CONTRIBUTING.md) file.

If you are new to Beats dev you can following the [developer
guide](https://www.elastic.co/guide/en/beats/libbeat/master/new-beat.html).

[See all contributors on GitHub](https://github.com/blacktop/brobeat/graphs/contributors).

Please update the [CHANGELOG.md](https://github.com/blacktop/brobeat/blob/master/CHANGELOG.md) and submit a [Pull Request on GitHub](https://help.github.com/articles/using-pull-requests/).

### License

Apache License (Version 2.0)  
Copyright (c) 2013 - 2016 **blacktop** Joshua Maine
