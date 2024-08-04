use std::sync::Mutex;

pub struct SharedBuffers {
    buffers: Mutex<Vec<Vec<u8>>>,
}
impl SharedBuffers {
    pub fn new() -> Self {
        Self {
            buffers: Mutex::new(Vec::new()),
        }
    }

    pub fn take(&self) -> Vec<u8> {
        let mut buff = self.buffers.lock().unwrap();
        match buff.pop() {
            Some(v) => v,
            None => Vec::new(),
        }

        //todo
    }
    pub fn release(&self, buffer: Vec<u8>) {
        let mut buff = self.buffers.lock().unwrap();
        buff.push(buffer)
    }
}
