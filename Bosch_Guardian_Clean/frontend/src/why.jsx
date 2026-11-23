import React from 'react';
import {buildWhy} from './why-logic.js';

export function WhyRisk({finding}) {
  const why = buildWhy(finding);
  if (!why) return null;
  return <div className="why-risk">
    <h4>Why this risk?</h4>
    <p className="why-chain">{why.steps.map((step, i) => <React.Fragment key={step}>
      {i > 0 && <span className="why-arrow"> → </span>}<span className="why-step">{step}</span></React.Fragment>)}
      <span className="why-arrow"> ⇒ </span><strong>{why.outcome}</strong></p>
    {why.adjustment && <p className="why-adjust">{why.adjustment}</p>}
    {why.confidence && <p className="why-meta">{why.confidence}</p>}
    {why.review.length > 0 && <p className="why-meta"><strong>Needs human review:</strong> {why.review.join('; ')}</p>}
  </div>;
}
