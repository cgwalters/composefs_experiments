pub mod image;
pub mod tar;

use std::io::Read;

use anyhow::Result;

use crate::{
    fsverity::Sha256HashValue,
    repository::Repository,
};

pub fn import_layer<R: Read>(repo: &Repository, name: &str, tar_stream: &mut R) -> Result<Sha256HashValue> {
    let mut writer = repo.create_stream(None);
    tar::split(tar_stream, &mut writer)?;
    repo.store_stream(writer, name)
}

pub fn import_layer_by_sha256<R: Read>(
    repo: &Repository,
    name: &str,
    tar_stream: &mut R,
    sha256: Sha256HashValue
) -> Result<()> {
    repo.store_stream_by_sha256(name, sha256, |writer| {
        tar::split(tar_stream, writer)
    })
}

pub fn ls_layer(repo: &Repository, name: &str) -> Result<()> {
    tar::ls(&mut repo.open_stream(name)?)
}

pub fn image(repo: &Repository, name: &str) -> Result<()> {
    image::merge(&mut repo.open_stream(name)?)
}
