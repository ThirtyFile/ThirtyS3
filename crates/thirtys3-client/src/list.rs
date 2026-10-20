//! Listing the objects of the bucket with `ListObjectsV2`.

use futures_util::StreamExt;
use futures_util::stream::BoxStream;
use http::Method;
use thirtys3_core::model::ListObjectsV2Result;

use crate::client::{Client, Spec};
use crate::error::Error;
use crate::meta::ObjectMeta;

/// The biggest answer of a listing that is read: 1000 entries of 1024-byte keys with all their other elements, with room to spare.
const LIST_ANSWER_LIMIT: usize = 8 * 1024 * 1024;

/// How to list.
#[derive(Debug, Clone, Default)]
pub struct ListOptions {
    /// Roll the keys that have this between the prefix and the next occurrence of it into one entry of `common_prefixes`, as folders. `/` for folders.
    pub delimiter: Option<String>,
    /// List only the keys after this one.
    pub start_after: Option<String>,
    /// How many entries to ask for in each request, 1 to 1000. The default of the service is 1000.
    pub page_size: Option<u32>,
}

/// One answer of a listing, or a whole listing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListPage {
    /// The objects.
    pub objects: Vec<ObjectMeta>,
    /// The common prefixes (with a delimiter).
    pub common_prefixes: Vec<String>,
}

impl Client {
    /// One request of a listing: the objects that start with `prefix`, after `continuation` when it is given. Returns the page and the token for
    /// the next one, `None` at the end. The prefix is a prefix of the key as it is: `photos/` lists the objects in that folder, `photos` also those
    /// of `photos-old/`.
    pub async fn list_page(&self, prefix: &str, options: &ListOptions, continuation: Option<&str>) -> Result<(ListPage, Option<String>), Error> {
        let mut parameters: Vec<(&str, String)> = vec![("encoding-type", "url".to_owned()), ("list-type", "2".to_owned())];
        if let Some(token) = continuation {
            parameters.push(("continuation-token", token.to_owned()));
        }
        if let Some(delimiter) = &options.delimiter {
            parameters.push(("delimiter", delimiter.clone()));
        }
        if let Some(size) = options.page_size {
            parameters.push(("max-keys", size.clamp(1, 1000).to_string()));
        }
        if !prefix.is_empty() {
            parameters.push(("prefix", prefix.to_owned()));
        }
        if let Some(start_after) = &options.start_after {
            parameters.push(("start-after", start_after.clone()));
        }
        let borrowed: Vec<(&str, &str)> = parameters.iter().map(|(name, value)| (*name, value.as_str())).collect();
        let spec = Spec::new(Method::GET, self.bucket_path()).query(&borrowed);
        let (_, body) = self.execute_for_body(&spec, LIST_ANSWER_LIMIT).await?;
        let result = ListObjectsV2Result::from_xml(&body)?;
        let objects = result
            .contents
            .into_iter()
            .map(|entry| ObjectMeta {
                key: entry.key,
                size: entry.size,
                last_modified: Some(entry.last_modified),
                etag: Some(entry.etag),
                storage_class: Some(entry.storage_class).filter(|class| class != "STANDARD"),
                ..ObjectMeta::default()
            })
            .collect();
        let next = if result.is_truncated {
            Some(result.next_continuation_token.ok_or_else(|| Error::Protocol("a truncated listing without NextContinuationToken".to_owned()))?)
        } else {
            None
        };
        Ok((ListPage { objects, common_prefixes: result.common_prefixes }, next))
    }

    /// A listing page by page, following the continuation tokens. Each item is one request's worth of entries (at most 1000).
    pub fn list_pages<'a>(&'a self, prefix: &'a str, options: &'a ListOptions) -> BoxStream<'a, Result<ListPage, Error>> {
        struct Position {
            token: Option<String>,
            finished: bool,
        }
        futures_util::stream::unfold(Position { token: None, finished: false }, move |position| async move {
            if position.finished {
                return None;
            }
            match self.list_page(prefix, options, position.token.as_deref()).await {
                Ok((page, next)) => Some((Ok(page), Position { finished: next.is_none(), token: next })),
                Err(error) => Some((Err(error), Position { token: None, finished: true })),
            }
        })
        .boxed()
    }

    /// All the objects whose keys start with `prefix`, in the order of their keys, as a stream. Requests are made as the stream is read.
    pub fn list<'a>(&'a self, prefix: &'a str, options: &'a ListOptions) -> BoxStream<'a, Result<ObjectMeta, Error>> {
        self.list_pages(prefix, options)
            .flat_map(|page| {
                futures_util::stream::iter(match page {
                    Ok(page) => page.objects.into_iter().map(Ok).collect::<Vec<_>>(),
                    Err(error) => vec![Err(error)],
                })
            })
            .boxed()
    }

    /// Everything under `prefix` with the keys rolled up at `delimiter`: the objects directly under it and the common prefixes ("folders"). All the
    /// pages are read.
    pub async fn list_with_delimiter(&self, prefix: &str, delimiter: &str) -> Result<ListPage, Error> {
        let options = ListOptions { delimiter: Some(delimiter.to_owned()), ..ListOptions::default() };
        let mut all = ListPage::default();
        let mut pages = self.list_pages(prefix, &options);
        while let Some(page) = pages.next().await {
            let page = page?;
            all.objects.extend(page.objects);
            all.common_prefixes.extend(page.common_prefixes);
        }
        Ok(all)
    }
}
