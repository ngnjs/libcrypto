# Contributing to NGN

Please be aware of and adhere to the coding practices. Pull requests that do not conform are unlikely to be accepted.

**NGN is designed to run on multiple JavaScript runtimes with a consistent API**. In other words, the same API should work in the browser, Node.js, and other supported runtimes. Runtime-specific API _features_ will not be accepted, but runtime-specific _implementations_ may be.

**_Example: Unacceptable_**
The following feature is only relevent to browsers:

```javascript
NGN.getHtmlElement = () => {
  ...
}
```

**_Example: Acceptable_**
The following feature is relevant to all runtimes, but the implementation differs by runtime:

```javascript
Object.defineProperty(NGN, 'platform', NGN.get(() => {
  let os

  /* node-only */
  os = process.platform
  /* end-node-only */
  /* browser-only */
  os = navigator.platform
  /* end-node-only */
}))
```

In the example above, creating a getter attribute to identify the current platform is relevant to all runtimes, but each runtime retrieves the data in a different manner. Since all runtimes are supported, this would be an acceptable contribution.

Technical compliance is not the only requirement. Even if a contribution meets the basic acceptance criteria, it does not mean it will be merged into the project. Introducing new features is a big maintenance consideration. If you want to add a new feature, propose it first and offer to work on it. The NGN team will do it's best to work through the proposal with you and provide guidance if/when necessary. Be mindful that the team has limited capacity, but will do as much as possible to assist.

## Source Code Considerations

As a _general practice_, all code should conform to **ECMAScript Final** features. This means Stage 3 and below will _not be accepted_. Most build/release tooling only supports final/stage 4 features.

### Exceptions to the Rule

**A petition may be made to use Stage 3 features when a) feature is highly likely to be adopted in ECMAScript Final and b) such use presents a significant, measurable, and predictable impact on the code base.** The NGN maintainer(s) reserve all rights to refuse such petitions. In layman's terms, we'll cherry pick specification features that make NGN better. Our goal is not to restrict features, it's to assure the maintainability and integrity of the project.

> **Example Exception:**
> The proposed Stage 3 public/private attributes can be used in NGN. NGN heavily utilizes private attributes/methods, which require significant boilerplate code to implement without the new proposal. Use of these new attributes are projected to reduce the code base size by 40%. This proposal was already implemented in V8 at the time (Chrome, Opera, Edge, Node.js) with no negative remarks from Mozilla (Firefox) or Apple (Safari).

Be mindful that the use of Stage 3 code may require modifications to the build and test environment ([@author.io/dev](https://github.com/author/dev)). This may or may not be a non-trivial effort for the NGN maintainers and may impact acceptance of a contribution.

## Unit Testing, Code Coverage, & Syntax

NGN uses the [@author.io/dev](https://github.com/author/dev) environment for creating, building, testing, and reporting. The primary components of this environment are:

- [rollup](https://rollupjs.org) is used for building modules.
- [terser](https://terserjs.org) is used for minifying distribution code.
- [tappedout](https://github.com/coreybutler/tappedout) for cross-runtime unit tests, based on [TAP](https://testanything.org). The @author.io/dev utility has a built in TAP parser to provide pretty formatting.
- [standard](https://standardjs.com) for syntax compliance. [snazzy](https://github.com/standard/snazzy) is used for producing human-readable results.
- [eslint](https://eslint.org) is used for compatibility reporting.

Github Actions are used to test and deploy releases.

## Understanding Releases

All releases are built and released automatically.

At present moment, **only ECMAScript Final source code will be accepted**. _No Stage 3 code will be shipped in a stable release_. If the code base uses any stage 3 features, they must be transpiled.

This project adhere's to [semantic versioning](https://semver.org/).

All releases must be approved by a project administrator.

### Official Releases

Official releases are available for modern browsers, Node.js 14.0.0+, and Deno. NGN will most likely work with prior versions of Node.js when ES Module support is enabled, but these versions are not officially supported.

##### Browser Releases

The _"current" distribution_ supports the last two years of major browser releases, on a rolling basis. The current edition is available in the default ES Module format.

NGN is distributed as minified JavaScript. Since this can be difficult to troubleshoot, each edition has a companion package containing relevant sourcemaps.

All core releases are shipped as `ngn`, while plugin releases are shipped to the npm registry under the `@ngnjs` organization.

1. ngn (current)
   - index.min.js
2. ngn-debug
   - index.min.js.map
3. @ngnjs/plugin
   - index.min.js
4. @ngnjs/plugin-debug
   - index.min.js.map

These releases are also available through popular CDN's (who support npm).
