import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

export const ProtectedAdminRoute = ({ children }) => {
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem('admin_token');
    if (!token) {
      navigate('/admin', { replace: true });
    }
  }, [navigate]);

  const token = localStorage.getItem('admin_token');
  return token ? children : null;
};
