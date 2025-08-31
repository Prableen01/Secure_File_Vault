import { useState } from 'react'
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import './App.css'

import EncryptPage from './EncryptPage';

function App() {
  const [count, setCount] = useState(0)

  return (
    <>
       <div>
      <h1>Secure File Vault</h1>
      <EncryptPage />
    </div>
    </>
  )
}

export default App
