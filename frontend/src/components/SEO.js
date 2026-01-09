import React from 'react';
import { Helmet } from 'react-helmet-async';

export const SEO = ({ 
  title = 'ZENVY - Modern E-Commerce Store', 
  description = 'Discover curated collections of trending products at ZENVY. From daily essentials to Instagram-worthy finds. Free shipping on orders over ₹999.',
  keywords = 'online shopping, ecommerce, trendy products, daily essentials, electronics, fashion, home decor, ZENVY',
  image = 'https://webstore-tracker.preview.emergentagent.com/og-image.jpg',
  url = 'https://webstore-tracker.preview.emergentagent.com'
}) => {
  return (
    <Helmet>
      {/* Primary Meta Tags */}
      <title>{title}</title>
      <meta name="title" content={title} />
      <meta name="description" content={description} />
      <meta name="keywords" content={keywords} />
      
      {/* Open Graph / Facebook */}
      <meta property="og:type" content="website" />
      <meta property="og:url" content={url} />
      <meta property="og:title" content={title} />
      <meta property="og:description" content={description} />
      <meta property="og:image" content={image} />
      
      {/* Twitter */}
      <meta property="twitter:card" content="summary_large_image" />
      <meta property="twitter:url" content={url} />
      <meta property="twitter:title" content={title} />
      <meta property="twitter:description" content={description} />
      <meta property="twitter:image" content={image} />
      
      {/* Additional SEO */}
      <meta name="robots" content="index, follow" />
      <meta name="language" content="English" />
      <meta name="revisit-after" content="7 days" />
      <meta name="author" content="ZENVY" />
      <link rel="canonical" href={url} />
      
      {/* Structured Data */}
      <script type="application/ld+json">
        {JSON.stringify({
          "@context": "https://schema.org",
          "@type": "OnlineStore",
          "name": "ZENVY",
          "description": description,
          "url": url,
          "logo": "https://webstore-tracker.preview.emergentagent.com/logo.png",
          "sameAs": [],
          "potentialAction": {
            "@type": "SearchAction",
            "target": `${url}/products?search={search_term_string}`,
            "query-input": "required name=search_term_string"
          }
        })}
      </script>
    </Helmet>
  );
};
