//! Which exported page answers a URL. The export has one HTML file per route, with
//! each dynamic segment exported once under a placeholder directory name
//! (`__site__`, `__privateKey__`, ...; see client/src/lib/routeParams.ts). A URL is
//! matched the way Next's router matches app routes: segment by segment, a static
//! segment beats a dynamic one, and a branch that leads to no page is abandoned for
//! the next candidate, so `/12/main` is `[site]/main` while `/12/abcdefabcdef/main`
//! is `[site]/[privateKey]/main`.

use std::{
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
};

#[derive(Debug, Default)]
pub struct RouteTree {
    root: Node,
    pages: usize,
}

#[derive(Debug, Default)]
struct Node {
    static_children: BTreeMap<String, Node>,
    /// The placeholder directory name (e.g. `__site__`) and its subtree
    dynamic_child: Option<(String, Box<Node>)>,
    /// The page's path in the export without extension, e.g. `__site__/main`
    page: Option<PathBuf>,
}

/// `__name__`: a dynamic segment exported with its placeholder value.
fn is_placeholder(segment: &str) -> bool {
    segment.len() > 4
        && segment.starts_with("__")
        && segment.ends_with("__")
        && segment[2..segment.len() - 2].bytes().all(|byte| byte.is_ascii_alphanumeric())
}

impl RouteTree {
    /// Reads every `*.html` page of an export directory. `404.html` and
    /// `_not-found.html` are the not-found page, not routes.
    pub fn scan(dir: &Path) -> io::Result<Self> {
        let mut tree = Self::default();
        let mut pending = vec![PathBuf::new()];
        while let Some(relative) = pending.pop() {
            for entry in std::fs::read_dir(dir.join(&relative))? {
                let entry = entry?;
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                let file_type = entry.file_type()?;
                if file_type.is_dir() {
                    // Build output, never a page
                    if relative.as_os_str().is_empty() && name == "_next" {
                        continue;
                    }
                    pending.push(relative.join(name));
                } else if let Some(stem) = name.strip_suffix(".html") {
                    let top_level = relative.as_os_str().is_empty();
                    if top_level && (stem == "404" || stem == "_not-found") {
                        continue;
                    }
                    tree.insert(&relative, stem);
                }
            }
        }
        Ok(tree)
    }

    fn insert(&mut self, relative_dir: &Path, stem: &str) {
        let mut segments: Vec<String> = relative_dir
            .components()
            .filter_map(|component| component.as_os_str().to_str().map(str::to_string))
            .collect();
        // index.html at the top is the root page
        if !(segments.is_empty() && stem == "index") {
            segments.push(stem.to_string());
        }

        let mut node = &mut self.root;
        for segment in &segments {
            node = if is_placeholder(segment) {
                let (_, child) = node
                    .dynamic_child
                    .get_or_insert_with(|| (segment.clone(), Box::default()));
                child
            } else {
                node.static_children.entry(segment.clone()).or_default()
            };
        }
        node.page = Some(relative_dir.join(stem));
        self.pages += 1;
    }

    pub fn page_count(&self) -> usize {
        self.pages
    }

    /// The exported page (path without extension) that answers `path`, a raw URL
    /// path such as `/12/main`.
    pub fn find(&self, path: &str) -> Option<&Path> {
        let trimmed = path.strip_prefix('/').unwrap_or(path);
        let segments: Vec<&str> = if trimmed.is_empty() { Vec::new() } else { trimmed.split('/').collect() };
        if segments.iter().any(|segment| segment.is_empty()) {
            return None;
        }
        find_in(&self.root, &segments)
    }
}

fn find_in<'a>(node: &'a Node, segments: &[&str]) -> Option<&'a Path> {
    let Some((first, rest)) = segments.split_first() else {
        return node.page.as_deref();
    };
    if let Some(found) = node.static_children.get(*first).and_then(|child| find_in(child, rest)) {
        return Some(found);
    }
    node.dynamic_child.as_ref().and_then(|(_, child)| find_in(child, rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The routes of client/src/app as the export lays them out.
    fn app_tree() -> RouteTree {
        let mut tree = RouteTree::default();
        let pages = [
            "index",
            "admin",
            "login",
            "signup",
            "settings",
            "settings/account",
            "as/callback",
            "__site__",
            "__site__/main",
            "__site__/sessions",
            "__site__/users",
            "__site__/dashboards",
            "__site__/dashboards/__dashboardId__",
            "__site__/user/__userId__",
            "__site__/__privateKey__/main",
            "__site__/__privateKey__/users",
            "__site__/__privateKey__/user/__userId__",
        ];
        for page in pages {
            let path = Path::new(page);
            let dir = path.parent().unwrap_or(Path::new(""));
            let stem = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
            tree.insert(dir, stem);
        }
        tree
    }

    fn page(tree: &RouteTree, path: &str) -> Option<String> {
        tree.find(path).map(|found| found.to_string_lossy().into_owned())
    }

    #[test]
    fn static_segments_win_over_dynamic_ones() {
        let tree = app_tree();
        assert_eq!(page(&tree, "/").as_deref(), Some("index"));
        assert_eq!(page(&tree, "/login").as_deref(), Some("login"));
        assert_eq!(page(&tree, "/settings/account").as_deref(), Some("settings/account"));
        assert_eq!(page(&tree, "/12/main").as_deref(), Some("__site__/main"));
        assert_eq!(page(&tree, "/12/dashboards").as_deref(), Some("__site__/dashboards"));
        assert_eq!(page(&tree, "/12/dashboards/7").as_deref(), Some("__site__/dashboards/__dashboardId__"));
        assert_eq!(page(&tree, "/12/user/abc").as_deref(), Some("__site__/user/__userId__"));
    }

    #[test]
    fn dynamic_segments_take_what_static_ones_do_not_match() {
        let tree = app_tree();
        assert_eq!(page(&tree, "/12/abcdefabcdef/main").as_deref(), Some("__site__/__privateKey__/main"));
        assert_eq!(
            page(&tree, "/12/abcdefabcdef/user/a%40b").as_deref(),
            Some("__site__/__privateKey__/user/__userId__")
        );
        // A static first segment without that page falls back to the site route
        assert_eq!(page(&tree, "/as").as_deref(), Some("__site__"));
        assert_eq!(page(&tree, "/favicon.ico").as_deref(), Some("__site__"));
        // `main` is a static child of [site], but [site]/main/main is no page, so the
        // router backtracks to [site]/[privateKey]/main
        assert_eq!(page(&tree, "/12/main/main").as_deref(), Some("__site__/__privateKey__/main"));
        // The `login` page has no children, so the router backtracks to [site]/users
        assert_eq!(page(&tree, "/login/users").as_deref(), Some("__site__/users"));
    }

    #[test]
    fn unknown_paths_match_nothing() {
        let tree = app_tree();
        assert_eq!(page(&tree, "/12/does-not-exist"), None);
        assert_eq!(page(&tree, "/12/user"), None);
        assert_eq!(page(&tree, "/12/abcdefabcdef"), None);
        assert_eq!(page(&tree, "/a/b/c/d/e"), None);
        assert_eq!(page(&tree, "/12//main"), None);
        assert_eq!(page(&tree, "/login/"), None);
    }

    #[test]
    fn placeholders_are_double_underscored_names() {
        assert!(is_placeholder("__site__"));
        assert!(is_placeholder("__privateKey__"));
        assert!(!is_placeholder("____"));
        assert!(!is_placeholder("_next"));
        assert!(!is_placeholder("__next.$d$site.txt"));
    }
}
