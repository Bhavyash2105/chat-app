import React from 'react';
import {Route, Routes} from "react-router-dom";
import Homepage from "./components/Homepage";
import SignIn from "./components/register/SignIn";
import SignUp from "./components/register/SignUp";
import VerifyOtp from "./components/register/VerifyOtp";

function App() {
    return (
        <div>
            <Routes>
                <Route path="/" element={<Homepage/>}/>
                <Route path='/signin' element={<SignIn/>}/>
                <Route path='/signup' element={<SignUp/>}/>
                <Route path='/verify-otp' element={<VerifyOtp/>}/>
            </Routes>
        </div>
    );
}

export default App;