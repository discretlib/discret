use std::sync::Arc;

///
/// there can be a large number af connections openned at the same time and we cannot afford to let each connection have their own buffers
///
pub struct SharedBuffers {
    buffers: Vec<Arc<tokio::sync::Mutex<Vec<u8>>>>,
    current: usize,
}
impl SharedBuffers {
    pub fn new(num_buffers: usize) -> Self {
        let mut buffers: Vec<Arc<tokio::sync::Mutex<Vec<u8>>>> = Vec::with_capacity(num_buffers);
        buffers.resize_with(num_buffers, Default::default);
        Self {
            buffers,
            current: 0,
        }
    }

    pub fn get(&mut self) -> Arc<tokio::sync::Mutex<Vec<u8>>> {
        let buffer = self.buffers[self.current].clone();

        self.current += 1;
        if self.current == self.buffers.len() {
            self.current = 0;
        }

        buffer
    }
}
