# Hello, World!

Thanks for your interest in making Metasploit -- and therefore, the
world -- a better place!

Are you about to report a bug? Sorry to hear it. Here's our [Issue tracker].
Please try to be as specific as you can about your problem, include steps
to reproduce (cut and paste from your console output if it's helpful), and
what you were expecting to happen.

Are you about to report a security vulnerability in Metasploit itself?
How ironic! Please take a look at Rapid7's [Vulnerability
Disclosure Policy](https://www.rapid7.com/disclosure.jsp), and send
your report to security@rapid7.com using our [PGP key].

Are you about to contribute some new functionality, a bug fix, or a new
Metasploit module? If so, read on...

# Contributing to Metasploit

What you see here in CONTRIBUTING.md is a bullet-point list of the do's
and don'ts of how to make sure *your* valuable contributions actually
make it into Metasploit's master branch.

If you care not to follow these rules, your contribution **will** be
closed (*Road House* style). Sorry!

This is intended to be a **short** list. The [wiki] is much more
exhaustive and reveals many mysteries. If you read nothing else, take a
look at the standard [development environment setup
guide](https://github.com/rapid7/metasploit-framework/wiki/Setting-Up-a-Metasploit-Development-Environment)
and Metasploit's [Common Coding Mistakes](https://github.com/rapid7/metasploit-framework/wiki/Common-Metasploit-Module-Coding-Mistakes).

## Code Contributions

* **Do** stick to the [Ruby style guide](https://github.com/bbatsov/ruby-style-guide).
* **Do** get [Rubocop](https://rubygems.org/search?query=rubocop) relatively quiet against the code you are adding or modifying.
* **Do** follow the [50/72 rule](http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html) for Git commit messages.
* **Don't** use the default merge messages when merging from other
   branches.
* **Do** create a [topic branch](http://git-scm.com/book/en/Git-Branching-Branching-Workflows#Topic-Branches) to work on instead of working directly on `master`.

### Pull Requests

* **Do** target your pull request to the **master branch**. Not staging, not develop, not release.
* **Do** specify a descriptive title to make searching for your pull request easier.
* **Do** include [console output](https://help.github.com/articles/github-flavored-markdown#fenced-code-blocks), especially for witnessable effects in `msfconsole`.
* **Do** list [verification steps](https://help.github.com/articles/writing-on-github#task-lists) so your code is testable.
* **Don't** leave your pull request description blank.
* **Don't** abandon your pull request. Being responsive helps us land your code faster.

Pull requests [#2940](https://github.com/rapid7/metasploit-framework/pull/2940) and [#3043](https://github.com/rapid7/metasploit-framework/pull/3043) are a couple good examples to follow.

#### New Modules

* **Do** run `tools/msftidy.rb` against your module and fix any errors or warnings that come up. Even better would be to set up `msftidy.rb` as a [pre-commit hook](https://github.com/rapid7/metasploit-framework/blob/master/tools/dev/pre-commit-hook.rb).
* **Do** use the [many module mixin APIs](https://rapid7.github.io/metasploit-framework/api/). Wheel improvements are welcome; wheel reinventions, not so much.
* **Don't** include more than one module per pull request.

#### Scripts

* **Don't** submit new [scripts]. Scripts are shipped as examples for automating local tasks, and anything "serious" can be done with post modules and local exploits.

#### Library Code

* **Do** write [RSpec](http://rspec.info/) tests - even the smallest change in library land can thoroughly screw things up.
* **Do** follow [Better Specs](http://betterspecs.org/) - it's like the style guide for specs.
* **Do** write [YARD](http://yardoc.org/) documentation - this makes it easier for people to use your code.
* **Don't** fix a lot of things in one pull request. Small fixes are easier to validate.

#### Bug Fixes

* **Do** include reproduction steps in the form of verification steps.
* **Do** include a link to any corresponding [Issue](https://github.com/rapid7/metasploit-framework/issues) in the format of `See #1234` in your commit description.

## Bug Reports

* **Do** report vulnerabilities in Rapid7 software directly to security@rapid7.com.
* **Do** write a detailed description of your bug and use a descriptive title.
* **Do** include reproduction steps, stack traces, and anything else that might help us verify and fix your bug.
* **Don't** file duplicate reports - search for your bug before filing a new report.

If you need some more guidance, talk to the main body of open
source contributors over on the [Freenode IRC channel](http://webchat.freenode.net/?channels=%23metasploit&uio=d4)
or e-mail us at [metasploit-hackers](https://lists.sourceforge.net/lists/listinfo/metasploit-hackers)
mailing list.

Also, **thank you** for taking the few moments to read this far! You're
already way ahead of the curve, so keep it up!

[Issue Tracker]:https://github.com/rapid7/metasploit-framework/issues
[PGP key]:http://pgp.mit.edu:11371/pks/lookup?op=vindex&search=0x2380F85B8AD4DB8D
[wiki]:https://github.com/rapid7/metasploit-framework/wiki
[scripts]: https://github.com/rapid7/metasploit-framework/tree/master/scripts
